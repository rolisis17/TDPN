package localapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/settlement"
)

const strongLocalAPIAuthToken = "localapi-test-token-1234567890abcdef"

type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func newFakeService(t *testing.T, allowUpdate bool) (*Service, string) {
	t.Helper()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "easy_node_fake.sh")
	logPath := filepath.Join(tmpDir, "easy_node_calls.log")

	script := `#!/usr/bin/env bash
set -euo pipefail
log_file="${LOCALAPI_TEST_LOG_FILE:?}"
cmd="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi

printf '%s' "$cmd" >>"$log_file"
for arg in "$@"; do
  printf '\t%s' "$arg" >>"$log_file"
done
printf '\n' >>"$log_file"

if [[ -n "${LOCALAPI_TEST_OUTPUT_BYTES:-}" ]]; then
  if [[ "${LOCALAPI_TEST_OUTPUT_BYTES}" =~ ^[0-9]+$ ]] && [[ "${LOCALAPI_TEST_OUTPUT_BYTES}" -gt 0 ]]; then
    head -c "${LOCALAPI_TEST_OUTPUT_BYTES}" < /dev/zero | tr '\0' 'A'
  fi
  exit 0
fi

case "$cmd" in
  client-vpn-preflight)
    bootstrap_directory=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --bootstrap-directory)
          bootstrap_directory="${2:-}"
          if [[ $# -gt 1 ]]; then
            shift 2
          else
            shift
          fi
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -n "${LOCALAPI_TEST_PREFLIGHT_FAIL_BOOTSTRAP:-}" && "$bootstrap_directory" == "${LOCALAPI_TEST_PREFLIGHT_FAIL_BOOTSTRAP}" ]]; then
      echo "preflight failed"
      exit 42
    fi
    if [[ "${LOCALAPI_TEST_PREFLIGHT_FAIL:-0}" == "1" ]]; then
      echo "preflight failed"
      exit 42
    fi
    echo "preflight ok"
    ;;
  client-vpn-up)
    subject_file=""
    bootstrap_directory=""
    saw_inline_subject="0"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --bootstrap-directory)
          bootstrap_directory="${2:-}"
          if [[ $# -gt 1 ]]; then
            shift 2
          else
            shift
          fi
          ;;
        --subject)
          saw_inline_subject="1"
          if [[ $# -gt 1 ]]; then
            shift 2
          else
            shift
          fi
          ;;
        --subject-file)
          subject_file="${2:-}"
          if [[ $# -gt 1 ]]; then
            shift 2
          else
            shift
          fi
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ "$saw_inline_subject" == "1" ]]; then
      echo "unexpected inline subject flag"
      exit 48
    fi
    if [[ -z "$subject_file" || ! -f "$subject_file" ]]; then
      echo "missing subject file"
      exit 48
    fi
    subject_value="$(tr -d '\r\n' <"$subject_file")"
    if [[ -z "$subject_value" ]]; then
      echo "empty subject file"
      exit 48
    fi
    if [[ "$subject_value" == *$'\n'* || "$subject_value" == *$'\r'* ]]; then
      echo "invalid subject value"
      exit 49
    fi
    if [[ -n "${LOCALAPI_TEST_EXPECT_SUBJECT_VALUE:-}" && "$subject_value" != "${LOCALAPI_TEST_EXPECT_SUBJECT_VALUE}" ]]; then
      echo "unexpected subject value: $subject_value"
      exit 47
    fi
    if [[ -n "${LOCALAPI_TEST_UP_FAIL_BOOTSTRAP:-}" && "$bootstrap_directory" == "${LOCALAPI_TEST_UP_FAIL_BOOTSTRAP}" ]]; then
      echo "connect failed"
      exit 43
    fi
    if [[ "${LOCALAPI_TEST_UP_FAIL:-0}" == "1" ]]; then
      echo "connect failed"
      exit 43
    fi
    if [[ -n "${LOCALAPI_TEST_BLOCK_STATE_PATH_AFTER_UP:-}" ]]; then
      rm -f "${LOCALAPI_TEST_BLOCK_STATE_PATH_AFTER_UP}"
      mkdir -p "${LOCALAPI_TEST_BLOCK_STATE_PATH_AFTER_UP}"
    fi
    echo "connect ok"
    ;;
  client-vpn-status)
    if [[ "${LOCALAPI_TEST_STATUS_FAIL:-0}" == "1" ]]; then
      echo "status failed"
      exit 44
    fi
    if [[ -n "${LOCALAPI_TEST_STATUS_JSON:-}" ]]; then
      echo "${LOCALAPI_TEST_STATUS_JSON}"
    elif [[ "${LOCALAPI_TEST_STATUS_RAW:-0}" == "1" ]]; then
      echo "status-raw"
    else
      echo '{"connected":true,"running":true,"interface":"wgvpn0","interface_state":"present","profile":"2hop","route_mode":"full-tunnel"}'
    fi
    ;;
  client-vpn-down)
    if [[ "${LOCALAPI_TEST_DOWN_FAIL:-0}" == "1" ]]; then
      echo "disconnect failed"
      exit 45
    fi
    echo "disconnect ok"
    ;;
  config-v1-set-profile)
    if [[ "${LOCALAPI_TEST_SET_PROFILE_FAIL:-0}" == "1" ]]; then
      echo "set profile failed"
      exit 46
    fi
    echo "set profile ok"
    ;;
  runtime-doctor)
    if [[ "${LOCALAPI_TEST_DIAG_RAW:-0}" == "1" ]]; then
      echo "diagnostics-raw"
    else
      echo '{"runtime":"ok"}'
    fi
    ;;
  self-update)
    if [[ "${LOCALAPI_TEST_UPDATE_FAIL:-0}" == "1" ]]; then
      echo "update failed"
      exit 47
    fi
    echo "update ok"
    ;;
  *)
    echo "ok"
    ;;
esac
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake script: %v", err)
	}
	if err := os.WriteFile(logPath, []byte{}, 0o644); err != nil {
		t.Fatalf("init fake script log: %v", err)
	}
	t.Setenv("LOCALAPI_TEST_LOG_FILE", logPath)

	svc := &Service{
		addr:                "127.0.0.1:8095",
		scriptPath:          scriptPath,
		commandTimeout:      5 * time.Second,
		maxConcurrentCmds:   defaultMaxCommands,
		commandSlots:        make(chan struct{}, defaultMaxCommands),
		allowUpdate:         allowUpdate,
		allowUnauthLoopback: true,
		// Keep default connect fixtures aligned with legacy-manual flow unless a test
		// explicitly exercises fail-closed override policy behavior.
		gpmAllowLegacyConnectOverride: true,
	}
	return svc, logPath
}

func callJSONHandler(t *testing.T, h http.HandlerFunc, method, path, body string) (int, map[string]any) {
	return callJSONHandlerWithHeaders(t, h, method, path, body, nil)
}

func callJSONHandlerWithHeaders(t *testing.T, h http.HandlerFunc, method, path, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodGet {
		if headers == nil {
			headers = map[string]string{}
		}
		if _, hasOrigin := headers["Origin"]; !hasOrigin {
			headers["Origin"] = "http://127.0.0.1:8095"
		}
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rr := httptest.NewRecorder()
	h(rr, req)

	out := map[string]any{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response json (status=%d body=%q): %v", rr.Code, rr.Body.String(), err)
	}
	return rr.Code, out
}

func callRouteStatus(t *testing.T, h http.Handler, method, path string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func seedGPMTestSession(t *testing.T, svc *Service, token string, walletAddress string, tier int, stakeSatisfied bool, prepaidSatisfied bool) string {
	t.Helper()
	if svc.gpmState == nil {
		svc.gpmState = newGPMRuntimeState()
	}
	if token == "" {
		token = "gpm-test-session-" + strings.TrimPrefix(walletAddress, "cosmos1")
	}
	svc.gpmState.putSession(gpmSession{
		Token:                   token,
		WalletAddress:           walletAddress,
		WalletProvider:          "keplr",
		Role:                    "client",
		WalletBindingVerified:   true,
		ClientTier:              tier,
		StakeSatisfied:          stakeSatisfied,
		PrepaidBalanceSatisfied: prepaidSatisfied,
		ExpiresAt:               time.Now().UTC().Add(time.Hour),
	})
	return token
}

func markGPMTestSessionEntitlementsTrusted(t *testing.T, svc *Service, token string) {
	t.Helper()
	if svc == nil || svc.gpmState == nil {
		t.Fatal("gpm state is required")
	}
	svc.gpmState.mu.Lock()
	defer svc.gpmState.mu.Unlock()
	session, ok := svc.gpmState.sessions[token]
	if !ok {
		t.Fatalf("session %q not found", token)
	}
	session.EntitlementEvidenceSource = "chain"
	svc.gpmState.sessions[token] = session
}

func markGPMTestSessionEntitlementsLocal(t *testing.T, svc *Service, token string) {
	t.Helper()
	if svc == nil || svc.gpmState == nil {
		t.Fatal("gpm state is required")
	}
	svc.gpmState.mu.Lock()
	defer svc.gpmState.mu.Unlock()
	session, ok := svc.gpmState.sessions[token]
	if !ok {
		t.Fatalf("session %q not found", token)
	}
	session.EntitlementEvidenceSource = "local_env"
	svc.gpmState.sessions[token] = session
}

func seedGPMTrustedTestSession(t *testing.T, svc *Service, token string, walletAddress string, tier int, stakeSatisfied bool, prepaidSatisfied bool) string {
	t.Helper()
	token = seedGPMTestSession(t, svc, token, walletAddress, tier, stakeSatisfied, prepaidSatisfied)
	markGPMTestSessionEntitlementsTrusted(t, svc, token)
	return token
}

func seedGPMUnboundTestSession(t *testing.T, svc *Service, token string, walletAddress string) string {
	t.Helper()
	if svc.gpmState == nil {
		svc.gpmState = newGPMRuntimeState()
	}
	if token == "" {
		token = "gpm-unbound-test-session-" + strings.TrimPrefix(walletAddress, "cosmos1")
	}
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         walletAddress,
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: false,
		ExpiresAt:             time.Now().UTC().Add(time.Hour),
	})
	return token
}

func trustGPMAdminTestPolicy(svc *Service, walletAddress string) {
	walletAddress = normalizeWalletAddress(walletAddress)
	if walletAddress == "" {
		return
	}
	if svc.gpmAdminWalletAllowlist == nil {
		svc.gpmAdminWalletAllowlist = map[string]struct{}{}
	}
	svc.gpmAdminWalletAllowlist[walletAddress] = struct{}{}
	if strings.TrimSpace(svc.gpmAuthVerifyCommand) == "" {
		svc.gpmAuthVerifyCommand = "test-command-backed-wallet-verifier"
	}
}

func seedGPMAdminTestSession(t *testing.T, svc *Service, token string, walletAddress string) string {
	t.Helper()
	if svc.gpmState == nil {
		svc.gpmState = newGPMRuntimeState()
	}
	if token == "" {
		token = "gpm-admin-test-session-" + strings.TrimPrefix(walletAddress, "cosmos1")
	}
	svc.gpmState.putSession(gpmSession{
		Token:                  token,
		WalletAddress:          walletAddress,
		WalletProvider:         "keplr",
		Role:                   "admin",
		WalletBindingVerified:  true,
		AuthVerificationSource: "command",
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              time.Now().UTC().Add(time.Hour),
	})
	trustGPMAdminTestPolicy(svc, walletAddress)
	return token
}

func gpmAdminSessionHeaders(t *testing.T, svc *Service, token string, walletAddress string) map[string]string {
	t.Helper()
	token = seedGPMAdminTestSession(t, svc, token, walletAddress)
	return map[string]string{"X-GPM-Session-Token": token}
}

func auditRecentAdminHeaders(t *testing.T, svc *Service) map[string]string {
	t.Helper()
	return gpmAdminSessionHeaders(t, svc, "gpm-audit-admin-token", "cosmos1auditadmin")
}

func TestGPMOperatorApplyRequiresWalletBoundSession(t *testing.T) {
	svc := &Service{
		addr:      "127.0.0.1:8095",
		authToken: "operator-apply-test-token",
		gpmState:  newGPMRuntimeState(),
	}
	token := seedGPMUnboundTestSession(t, svc, "gpm-unbound-operator-apply", "cosmos1operatorapply")
	body := fmt.Sprintf(`{"session_token":%q,"chain_operator_id":"gpmvaloper1operator","server_label":"operator-a"}`, token)
	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMOperatorApply, http.MethodPost, "/v1/gpm/operator/apply", body, map[string]string{
		"Authorization": "Bearer operator-apply-test-token",
	})
	if code != http.StatusForbidden {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if _, ok := svc.gpmState.getOperator("cosmos1operatorapply"); ok {
		t.Fatalf("unbound session should not persist operator application")
	}
}

func readCommandLog(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	content := strings.TrimSpace(string(raw))
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	out := make([][]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, strings.Split(line, "\t"))
	}
	return out
}

func readAuditLogRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	content := strings.TrimSpace(string(body))
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		record := map[string]any{}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode audit line: %v", err)
		}
		records = append(records, record)
	}
	return records
}

func commandFlags(parts []string) map[string]string {
	flags := map[string]string{}
	for i := 1; i < len(parts); i++ {
		token := parts[i]
		if !strings.HasPrefix(token, "--") {
			continue
		}
		value := ""
		if i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "--") {
			value = parts[i+1]
			i++
		}
		flags[token] = value
	}
	return flags
}

func mustFlagValue(t *testing.T, parts []string, flag, want string) {
	t.Helper()
	flags := commandFlags(parts)
	got, ok := flags[flag]
	if !ok {
		t.Fatalf("missing flag %s in command %q", flag, strings.Join(parts, " "))
	}
	if got != want {
		t.Fatalf("flag %s=%q want=%q in command %q", flag, got, want, strings.Join(parts, " "))
	}
}

func mustFlagNonEmptyValue(t *testing.T, parts []string, flag string) string {
	t.Helper()
	flags := commandFlags(parts)
	got, ok := flags[flag]
	if !ok {
		t.Fatalf("missing flag %s in command %q", flag, strings.Join(parts, " "))
	}
	if strings.TrimSpace(got) == "" {
		t.Fatalf("flag %s has empty value in command %q", flag, strings.Join(parts, " "))
	}
	return got
}

func mustNotHaveFlag(t *testing.T, parts []string, flag string) {
	t.Helper()
	if _, ok := commandFlags(parts)[flag]; ok {
		t.Fatalf("flag %s should not be present in command %q", flag, strings.Join(parts, " "))
	}
}

func mustNotContainToken(t *testing.T, parts []string, token string) {
	t.Helper()
	for _, part := range parts {
		if part == token {
			t.Fatalf("token %q should not be present in command %q", token, strings.Join(parts, " "))
		}
	}
}

func lifecycleSuccessCommand(output string) string {
	output = strings.TrimSpace(output)
	if runtime.GOOS == "windows" {
		escaped := strings.ReplaceAll(output, "'", "''")
		return fmt.Sprintf("powershell -NoProfile -Command \"Write-Output '%s'\"", escaped)
	}
	return fmt.Sprintf("printf %s", output)
}

func lifecycleFailureCommand(output string, exitCode int) string {
	output = strings.TrimSpace(output)
	if runtime.GOOS == "windows" {
		escaped := strings.ReplaceAll(output, "'", "''")
		return fmt.Sprintf("powershell -NoProfile -Command \"Write-Output '%s'; exit %d\"", escaped, exitCode)
	}
	return fmt.Sprintf("sh -c \"printf %s; exit %d\"", output, exitCode)
}

func lifecycleOversizedOutputCommand() string {
	if runtime.GOOS == "windows" {
		return "powershell -NoProfile -Command \"$chunk = 'B' * 1024; 1..2048 | ForEach-Object { Write-Host -NoNewline $chunk }\""
	}
	return "sh -c \"head -c 2097152 < /dev/zero | tr '\\000' 'B'\""
}

func authVerifierCommandExpectSignature(expected string, failOutput string, failCode int) string {
	expected = strings.TrimSpace(expected)
	failOutput = strings.TrimSpace(failOutput)
	if runtime.GOOS == "windows" {
		escapedExpected := strings.ReplaceAll(expected, "'", "''")
		escapedFailOutput := strings.ReplaceAll(failOutput, "'", "''")
		return fmt.Sprintf(
			"powershell -NoProfile -Command \"if (($env:GPM_AUTH_VERIFY_SIGNATURE -eq '%s') -and -not [string]::IsNullOrWhiteSpace($env:GPM_AUTH_VERIFY_CHALLENGE_ID)) { exit 0 }; Write-Output '%s'; exit %d\"",
			escapedExpected,
			escapedFailOutput,
			failCode,
		)
	}
	return fmt.Sprintf(
		"sh -c \"if [ \\\"$GPM_AUTH_VERIFY_SIGNATURE\\\" = '%s' ] && [ -n \\\"$GPM_AUTH_VERIFY_CHALLENGE_ID\\\" ]; then exit 0; fi; echo %s; exit %d\"",
		expected,
		failOutput,
		failCode,
	)
}

func authVerifierCommandExpectSignatureMetadata(expectedSignature string, expectedMetadata gpmAuthSignatureMetadata, failOutput string, failCode int) string {
	expectedSignature = strings.TrimSpace(expectedSignature)
	failOutput = strings.TrimSpace(failOutput)
	if runtime.GOOS == "windows" {
		escapedSignature := strings.ReplaceAll(expectedSignature, "'", "''")
		escapedSignatureKind := strings.ReplaceAll(expectedMetadata.SignatureKind, "'", "''")
		escapedSignaturePublicKey := strings.ReplaceAll(expectedMetadata.SignaturePublicKey, "'", "''")
		escapedSignaturePublicKeyType := strings.ReplaceAll(expectedMetadata.SignaturePublicKeyType, "'", "''")
		escapedSignatureSource := strings.ReplaceAll(expectedMetadata.SignatureSource, "'", "''")
		escapedChainID := strings.ReplaceAll(expectedMetadata.ChainID, "'", "''")
		escapedSignedMessage := strings.ReplaceAll(expectedMetadata.SignedMessage, "'", "''")
		escapedSignatureEnvelope := strings.ReplaceAll(expectedMetadata.SignatureEnvelope, "'", "''")
		escapedFailOutput := strings.ReplaceAll(failOutput, "'", "''")
		return fmt.Sprintf(
			"powershell -NoProfile -Command \"if (($env:GPM_AUTH_VERIFY_SIGNATURE -eq '%s') -and ($env:GPM_AUTH_VERIFY_SIGNATURE_KIND -eq '%s') -and ($env:GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY -eq '%s') -and ($env:GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE -eq '%s') -and ($env:GPM_AUTH_VERIFY_SIGNATURE_SOURCE -eq '%s') -and ($env:GPM_AUTH_VERIFY_CHAIN_ID -eq '%s') -and ($env:GPM_AUTH_VERIFY_SIGNED_MESSAGE -eq '%s') -and ($env:GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE -eq '%s') -and -not [string]::IsNullOrWhiteSpace($env:GPM_AUTH_VERIFY_CHALLENGE_ID)) { exit 0 }; Write-Output '%s'; exit %d\"",
			escapedSignature,
			escapedSignatureKind,
			escapedSignaturePublicKey,
			escapedSignaturePublicKeyType,
			escapedSignatureSource,
			escapedChainID,
			escapedSignedMessage,
			escapedSignatureEnvelope,
			escapedFailOutput,
			failCode,
		)
	}
	return fmt.Sprintf(
		"sh -c \"if [ \\\"$GPM_AUTH_VERIFY_SIGNATURE\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_SIGNATURE_KIND\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_SIGNATURE_SOURCE\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_CHAIN_ID\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_SIGNED_MESSAGE\\\" = '%s' ] && [ \\\"$GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE\\\" = '%s' ] && [ -n \\\"$GPM_AUTH_VERIFY_CHALLENGE_ID\\\" ]; then exit 0; fi; echo %s; exit %d\"",
		expectedSignature,
		expectedMetadata.SignatureKind,
		expectedMetadata.SignaturePublicKey,
		expectedMetadata.SignaturePublicKeyType,
		expectedMetadata.SignatureSource,
		expectedMetadata.ChainID,
		expectedMetadata.SignedMessage,
		expectedMetadata.SignatureEnvelope,
		failOutput,
		failCode,
	)
}

func deterministicEd25519Proof(message string) (signatureBase64 string, publicKeyBase64 string) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, []byte(message))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(signature), base64.StdEncoding.EncodeToString(publicKey)
}

func deterministicSecp256k1Proof(message string) (signatureBase64 string, publicKeyBase64 string) {
	privateKey := big.NewInt(1)
	hash := sha256.Sum256([]byte(message))
	nonceSeed := sha256.Sum256([]byte("gpm-auth-secp256k1-test-nonce:" + message))
	maxNonce := new(big.Int).Sub(new(big.Int).Set(secp256k1CurveOrder), big.NewInt(1))
	nonce := new(big.Int).SetBytes(nonceSeed[:])
	nonce.Mod(nonce, maxNonce)
	nonce.Add(nonce, big.NewInt(1))

	generator := newSecp256k1Point(secp256k1GeneratorX, secp256k1GeneratorY)

	var r *big.Int
	var s *big.Int
	for attempts := 0; attempts < 8; attempts++ {
		noncePoint := secp256k1ScalarMult(generator, nonce)
		if !noncePoint.Infinity && noncePoint.X != nil {
			candidateR := new(big.Int).Mod(noncePoint.X, secp256k1CurveOrder)
			if candidateR.Sign() != 0 {
				nonceInv := new(big.Int).ModInverse(nonce, secp256k1CurveOrder)
				if nonceInv != nil {
					candidateS := new(big.Int).Mul(candidateR, privateKey)
					candidateS.Add(candidateS, new(big.Int).SetBytes(hash[:]))
					candidateS.Mul(candidateS, nonceInv)
					candidateS.Mod(candidateS, secp256k1CurveOrder)
					if candidateS.Sign() != 0 {
						r = candidateR
						s = candidateS
						break
					}
				}
			}
		}
		nonce.Add(nonce, big.NewInt(1))
		if nonce.Cmp(secp256k1CurveOrder) >= 0 {
			nonce.SetInt64(1)
		}
	}
	if r == nil || s == nil {
		panic("failed to derive deterministic secp256k1 signature")
	}

	publicKeyPoint := secp256k1ScalarMult(generator, privateKey)
	if publicKeyPoint.Infinity || publicKeyPoint.X == nil || publicKeyPoint.Y == nil {
		panic("failed to derive deterministic secp256k1 public key")
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):], sBytes)

	publicKey := make([]byte, 33)
	publicKey[0] = 0x02
	if publicKeyPoint.Y.Bit(0) == 1 {
		publicKey[0] = 0x03
	}
	xBytes := publicKeyPoint.X.Bytes()
	copy(publicKey[33-len(xBytes):], xBytes)

	return base64.StdEncoding.EncodeToString(signature), base64.StdEncoding.EncodeToString(publicKey)
}

type gpmRewardFinalizeConfirmationAdapter struct {
	confirmRewards    bool
	rewardSubmitCalls int
	rewards           map[string]settlement.RewardIssue
	slashEvidence     []settlement.SlashEvidence
	slashListCalls    []settlement.SlashEvidenceFilter
}

func (a *gpmRewardFinalizeConfirmationAdapter) SubmitSessionSettlement(context.Context, settlement.SessionSettlement) (string, error) {
	return "session-chain-ref", nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) SubmitRewardIssue(_ context.Context, reward settlement.RewardIssue) (string, error) {
	a.rewardSubmitCalls++
	if a.rewards == nil {
		a.rewards = map[string]settlement.RewardIssue{}
	}
	a.rewards[reward.RewardID] = reward
	return "reward-chain-ref-" + reward.RewardID, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) SubmitSponsorReservation(context.Context, settlement.SponsorCreditReservation) (string, error) {
	return "sponsor-chain-ref", nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) SubmitSlashEvidence(context.Context, settlement.SlashEvidence) (string, error) {
	return "slash-chain-ref", nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) Health(context.Context) error {
	return nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) HasSessionSettlement(context.Context, string) (bool, error) {
	return false, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) HasRewardIssue(context.Context, string) (bool, error) {
	return a.confirmRewards, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) HasSponsorReservation(context.Context, string) (bool, error) {
	return false, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) HasSlashEvidence(context.Context, string) (bool, error) {
	return false, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) SessionSettlementStatus(context.Context, string) (settlement.OperationStatus, bool, error) {
	return "", false, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) RewardIssueStatus(context.Context, string) (settlement.OperationStatus, bool, error) {
	if !a.confirmRewards {
		return settlement.OperationStatusSubmitted, true, nil
	}
	return settlement.OperationStatusConfirmed, true, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) RewardIssue(_ context.Context, rewardID string) (settlement.RewardIssue, bool, error) {
	reward, ok := a.rewards[rewardID]
	if !ok {
		return settlement.RewardIssue{}, false, nil
	}
	if a.confirmRewards {
		reward.Status = settlement.OperationStatusConfirmed
	} else {
		reward.Status = settlement.OperationStatusSubmitted
	}
	return reward, true, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) SponsorReservationStatus(context.Context, string) (settlement.OperationStatus, bool, error) {
	return "", false, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) SlashEvidenceStatus(context.Context, string) (settlement.OperationStatus, bool, error) {
	return "", false, nil
}

func (a *gpmRewardFinalizeConfirmationAdapter) ListSlashEvidence(_ context.Context, filter settlement.SlashEvidenceFilter) ([]settlement.SlashEvidence, error) {
	a.slashListCalls = append(a.slashListCalls, filter)
	out := make([]settlement.SlashEvidence, 0, len(a.slashEvidence))
	for _, evidence := range a.slashEvidence {
		if strings.TrimSpace(filter.SubjectID) != "" && strings.TrimSpace(evidence.SubjectID) != strings.TrimSpace(filter.SubjectID) {
			continue
		}
		if strings.TrimSpace(filter.SessionID) != "" && strings.TrimSpace(evidence.SessionID) != strings.TrimSpace(filter.SessionID) {
			continue
		}
		if strings.TrimSpace(filter.ViolationType) != "" && strings.TrimSpace(evidence.ViolationType) != strings.TrimSpace(filter.ViolationType) {
			continue
		}
		if evidence.ObservedAt.IsZero() && !filter.IncludeZeroObserved {
			continue
		}
		if !evidence.ObservedAt.IsZero() {
			if !filter.ObservedAtOrAfter.IsZero() && evidence.ObservedAt.Before(filter.ObservedAtOrAfter) {
				continue
			}
			if !filter.ObservedBefore.IsZero() && !evidence.ObservedAt.Before(filter.ObservedBefore) {
				continue
			}
		}
		out = append(out, evidence)
	}
	return out, nil
}

type gpmNoSlashEvidenceListService struct {
	settlement.Service
}

type gpmReserveFundsFinalityService struct {
	settlement.Service
	returnedStatus settlement.OperationStatus
	chainStatus    settlement.OperationStatus
	chainFound     bool
	chainErr       error
	reservation    settlement.FundReservation
	reservationOK  bool
	reservationErr error
}

func (s *gpmReserveFundsFinalityService) ReserveFunds(_ context.Context, reservation settlement.FundReservation) (settlement.FundReservation, error) {
	if strings.TrimSpace(reservation.ReservationID) == "" {
		reservation.ReservationID = "res-" + strings.TrimSpace(reservation.SessionID)
	}
	if strings.TrimSpace(reservation.Currency) == "" {
		reservation.Currency = "TDPNC"
	}
	if reservation.CreatedAt.IsZero() {
		reservation.CreatedAt = time.Now().UTC()
	}
	reservation.Status = s.returnedStatus
	if reservation.Status == "" {
		reservation.Status = settlement.OperationStatusSubmitted
	}
	return reservation, nil
}

func (s *gpmReserveFundsFinalityService) FundReservationStatus(context.Context, string) (settlement.OperationStatus, bool, error) {
	return s.chainStatus, s.chainFound, s.chainErr
}

func (s *gpmReserveFundsFinalityService) FundReservation(_ context.Context, reservationID string) (settlement.FundReservation, bool, error) {
	if s.reservationErr != nil {
		return settlement.FundReservation{}, false, s.reservationErr
	}
	if !s.reservationOK {
		return settlement.FundReservation{}, false, nil
	}
	reservation := s.reservation
	if strings.TrimSpace(reservation.ReservationID) == "" {
		reservation.ReservationID = strings.TrimSpace(reservationID)
	}
	return reservation, true, nil
}

type gpmReserveFundsChainStatusAdapter struct {
	status                 settlement.OperationStatus
	found                  bool
	submittedReservations  []settlement.FundReservation
	reservationStatusCalls []string
}

func (a *gpmReserveFundsChainStatusAdapter) SubmitSessionSettlement(context.Context, settlement.SessionSettlement) (string, error) {
	return "session-chain-ref", nil
}

func (a *gpmReserveFundsChainStatusAdapter) SubmitFundReservation(_ context.Context, reservation settlement.FundReservation) (string, error) {
	a.submittedReservations = append(a.submittedReservations, reservation)
	return "reservation-chain-ref-" + reservation.ReservationID, nil
}

func (a *gpmReserveFundsChainStatusAdapter) SubmitRewardIssue(context.Context, settlement.RewardIssue) (string, error) {
	return "reward-chain-ref", nil
}

func (a *gpmReserveFundsChainStatusAdapter) SubmitSponsorReservation(context.Context, settlement.SponsorCreditReservation) (string, error) {
	return "sponsor-chain-ref", nil
}

func (a *gpmReserveFundsChainStatusAdapter) SubmitSlashEvidence(context.Context, settlement.SlashEvidence) (string, error) {
	return "slash-chain-ref", nil
}

func (a *gpmReserveFundsChainStatusAdapter) Health(context.Context) error {
	return nil
}

func (a *gpmReserveFundsChainStatusAdapter) FundReservationStatus(_ context.Context, reservationID string) (settlement.OperationStatus, bool, error) {
	a.reservationStatusCalls = append(a.reservationStatusCalls, reservationID)
	return a.status, a.found, nil
}

func TestNormalizePathProfile(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "2hop"},
		{in: "2hop", want: "2hop"},
		{in: "balanced", want: "2hop"},
		{in: "1hop", want: "1hop"},
		{in: "speed", want: "2hop"},
		{in: "speed-1hop", want: "1hop"},
		{in: "3hop", want: "3hop"},
		{in: "private", want: "3hop"},
		{in: " FAST ", want: "2hop"},
		{in: " PRIVACY ", want: "3hop"},
		{in: " 2 ", want: "2hop"},
		{in: "bad", want: ""},
	}
	for _, tc := range tests {
		if got := normalizePathProfile(tc.in); got != tc.want {
			t.Fatalf("normalizePathProfile(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}

func TestBoolTo01(t *testing.T) {
	if got := boolTo01(true); got != "1" {
		t.Fatalf("boolTo01(true)=%q", got)
	}
	if got := boolTo01(false); got != "0" {
		t.Fatalf("boolTo01(false)=%q", got)
	}
}

func TestWriteSecretTempFile(t *testing.T) {
	path, cleanup, err := writeSecretTempFile("localapi-test-", "invite-secret")
	if err != nil {
		t.Fatalf("writeSecretTempFile returned err: %v", err)
	}
	if cleanup == nil {
		t.Fatal("writeSecretTempFile returned nil cleanup")
	}
	defer cleanup()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if string(content) != "invite-secret" {
		t.Fatalf("temp file content=%q want=%q", string(content), "invite-secret")
	}

	cleanup()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cleanup to remove file, stat err=%v", err)
	}
}

func TestWriteSecretTempFileRejectsEmptySecret(t *testing.T) {
	if _, _, err := writeSecretTempFile("localapi-test-", "   "); err == nil {
		t.Fatal("expected empty secret to be rejected")
	}
}

func TestNewDefaultsAndOverrides(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_ADDR", "")
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", "")
		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UPDATE", "")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "")
		t.Setenv(allowInsecureHTTPEnv, "")
		t.Setenv(maxCommandsEnv, "")
		t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", "")
		t.Setenv("GPM_PRODUCTION_MODE", "")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")
		t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("GPM_ADMIN_CONSOLE", "")
		t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "")
		t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "")

		s := New()
		if s.addr != defaultAddr {
			t.Fatalf("addr=%q want=%q", s.addr, defaultAddr)
		}
		if s.scriptPath != "" && !filepath.IsAbs(s.scriptPath) {
			t.Fatalf("scriptPath should be absolute or disabled, got=%q", s.scriptPath)
		}
		if s.commandRunner != "" {
			t.Fatalf("commandRunner=%q want empty", s.commandRunner)
		}
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("commandTimeout=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}
		if s.maxConcurrentCmds != defaultMaxCommands {
			t.Fatalf("maxConcurrentCmds=%d want=%d", s.maxConcurrentCmds, defaultMaxCommands)
		}
		if cap(s.commandSlots) != defaultMaxCommands {
			t.Fatalf("commandSlots cap=%d want=%d", cap(s.commandSlots), defaultMaxCommands)
		}
		if s.allowUpdate {
			t.Fatalf("allowUpdate=%t want=false", s.allowUpdate)
		}
		if s.allowUnauthLoopback {
			t.Fatalf("allowUnauthLoopback=%t want=false", s.allowUnauthLoopback)
		}
		if s.allowInsecureHTTP {
			t.Fatalf("allowInsecureHTTP=%t want=false", s.allowInsecureHTTP)
		}
		if s.authToken != "" {
			t.Fatalf("authToken=%q want empty", s.authToken)
		}
		if s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=false", s.gpmConnectRequireSession)
		}
		if s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=false", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "default" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=default",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
		}
		if s.gpmAdminRoutesEnabled {
			t.Fatalf("gpmAdminRoutesEnabled=%t want=false", s.gpmAdminRoutesEnabled)
		}
		if s.gpmAdminRoutesSource != "default" {
			t.Fatalf("gpmAdminRoutesSource=%q want=default", s.gpmAdminRoutesSource)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrap {
			t.Fatalf("gpmLegacyConnectRequireTrustedManifestBootstrap=%t want=false", s.gpmLegacyConnectRequireTrustedManifestBootstrap)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrapSource != "default" {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrapSource=%q want=default",
				s.gpmLegacyConnectRequireTrustedManifestBootstrapSource,
			)
		}
		if s.gpmConnectPolicyMode != "default" {
			t.Fatalf("gpmConnectPolicyMode=%q want=default", s.gpmConnectPolicyMode)
		}
		if s.gpmConnectPolicySource != "default" {
			t.Fatalf("gpmConnectPolicySource=%q want=default", s.gpmConnectPolicySource)
		}
		if s.gpmManifestTrustPolicyMode != "default" {
			t.Fatalf("gpmManifestTrustPolicyMode=%q want=default", s.gpmManifestTrustPolicyMode)
		}
		if s.gpmManifestTrustPolicySource != "default" {
			t.Fatalf("gpmManifestTrustPolicySource=%q want=default", s.gpmManifestTrustPolicySource)
		}
		if s.gpmManifestRequireHTTPS {
			t.Fatalf("gpmManifestRequireHTTPS=%t want=false", s.gpmManifestRequireHTTPS)
		}
		if s.gpmManifestRequireSignature {
			t.Fatalf("gpmManifestRequireSignature=%t want=false", s.gpmManifestRequireSignature)
		}
		if s.gpmManifestRequireHTTPSSource != "default" {
			t.Fatalf("gpmManifestRequireHTTPSSource=%q want=default", s.gpmManifestRequireHTTPSSource)
		}
		if s.gpmManifestRequireSigSource != "default" {
			t.Fatalf("gpmManifestRequireSigSource=%q want=default", s.gpmManifestRequireSigSource)
		}
		if s.gpmManifestRemoteRefreshIntvl != 5*time.Minute {
			t.Fatalf("gpmManifestRemoteRefreshIntvl=%s want=5m0s", s.gpmManifestRemoteRefreshIntvl)
		}
		if s.gpmManifestRemoteRefreshSrc != "default" {
			t.Fatalf("gpmManifestRemoteRefreshSrc=%q want=default", s.gpmManifestRemoteRefreshSrc)
		}
		if s.gpmManifestRefreshFailureMaxCacheAge != 0 {
			t.Fatalf("gpmManifestRefreshFailureMaxCacheAge=%s want=0s", s.gpmManifestRefreshFailureMaxCacheAge)
		}
		if s.gpmManifestRefreshFailureMaxCacheAgeSrc != "default" {
			t.Fatalf("gpmManifestRefreshFailureMaxCacheAgeSrc=%q want=default", s.gpmManifestRefreshFailureMaxCacheAgeSrc)
		}
		if s.gpmAuthVerifyPolicyMode != "default" {
			t.Fatalf("gpmAuthVerifyPolicyMode=%q want=default", s.gpmAuthVerifyPolicyMode)
		}
		if s.gpmAuthVerifyPolicySource != "default" {
			t.Fatalf("gpmAuthVerifyPolicySource=%q want=default", s.gpmAuthVerifyPolicySource)
		}
		if s.gpmAuthVerifyRequireCommand {
			t.Fatalf("gpmAuthVerifyRequireCommand=%t want=false", s.gpmAuthVerifyRequireCommand)
		}
		if s.gpmAuthVerifyRequireCmdSource != "default" {
			t.Fatalf("gpmAuthVerifyRequireCmdSource=%q want=default", s.gpmAuthVerifyRequireCmdSource)
		}
		if s.gpmAuthVerifyRequireMetadata {
			t.Fatalf("gpmAuthVerifyRequireMetadata=%t want=false", s.gpmAuthVerifyRequireMetadata)
		}
		if s.gpmAuthVerifyRequireWalletExt {
			t.Fatalf("gpmAuthVerifyRequireWalletExt=%t want=false", s.gpmAuthVerifyRequireWalletExt)
		}
		if s.gpmAuthVerifyMetadataSource != "default" {
			t.Fatalf("gpmAuthVerifyMetadataSource=%q want=default", s.gpmAuthVerifyMetadataSource)
		}
		if s.gpmAuthVerifyWalletExtSource != "default" {
			t.Fatalf("gpmAuthVerifyWalletExtSource=%q want=default", s.gpmAuthVerifyWalletExtSource)
		}
		if s.gpmAuthVerifyRequireCryptoProof {
			t.Fatalf("gpmAuthVerifyRequireCryptoProof=%t want=false", s.gpmAuthVerifyRequireCryptoProof)
		}
		if s.gpmAuthVerifyCryptoSource != "default" {
			t.Fatalf("gpmAuthVerifyCryptoSource=%q want=default", s.gpmAuthVerifyCryptoSource)
		}
		if got := len(s.gpmLegacyEnvAliasesActive); got != 0 {
			t.Fatalf("gpmLegacyEnvAliasesActive len=%d want=0", got)
		}
		if got := len(s.gpmLegacyEnvAliasWarnings); got != 0 {
			t.Fatalf("gpmLegacyEnvAliasWarnings len=%d want=0", got)
		}
	})

	t.Run("default role cannot mint admin sessions", func(t *testing.T) {
		t.Setenv("GPM_DEFAULT_ROLE", "admin")
		s := New()
		if s.gpmRoleDefault != "client" {
			t.Fatalf("gpmRoleDefault=%q want=client", s.gpmRoleDefault)
		}
	})

	t.Run("admin routes require explicit daemon opt in", func(t *testing.T) {
		t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "1")
		t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("GPM_ADMIN_CONSOLE", "")
		t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "")
		t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "")

		s := New()
		if !s.gpmAdminRoutesEnabled {
			t.Fatalf("gpmAdminRoutesEnabled=%t want=true", s.gpmAdminRoutesEnabled)
		}
		if s.gpmAdminRoutesSource != "GPM_LOCAL_API_ADMIN_ROUTES" {
			t.Fatalf("gpmAdminRoutesSource=%q want=GPM_LOCAL_API_ADMIN_ROUTES", s.gpmAdminRoutesSource)
		}
	})

	t.Run("admin console ui mode does not enable daemon admin routes", func(t *testing.T) {
		t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("GPM_ADMIN_CONSOLE", "1")
		t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "1")
		t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "1")

		s := New()
		if s.gpmAdminRoutesEnabled {
			t.Fatalf("gpmAdminRoutesEnabled=%t want=false", s.gpmAdminRoutesEnabled)
		}
		if s.gpmAdminRoutesSource != "default" {
			t.Fatalf("gpmAdminRoutesSource=%q want=default", s.gpmAdminRoutesSource)
		}
	})

	t.Run("explicit disabled admin route env is not overridden by ui mode", func(t *testing.T) {
		t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "0")
		t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("GPM_ADMIN_CONSOLE", "1")
		t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "1")
		t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "1")

		s := New()
		if s.gpmAdminRoutesEnabled {
			t.Fatalf("gpmAdminRoutesEnabled=%t want=false", s.gpmAdminRoutesEnabled)
		}
		if s.gpmAdminRoutesSource != "GPM_LOCAL_API_ADMIN_ROUTES" {
			t.Fatalf("gpmAdminRoutesSource=%q want=GPM_LOCAL_API_ADMIN_ROUTES", s.gpmAdminRoutesSource)
		}
	})

	t.Run("invalid admin route opt in fails closed", func(t *testing.T) {
		t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "sometimes")
		t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
		t.Setenv("GPM_ADMIN_CONSOLE", "")
		t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "")
		t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "")

		s := New()
		if s.gpmAdminRoutesEnabled {
			t.Fatalf("gpmAdminRoutesEnabled=%t want=false", s.gpmAdminRoutesEnabled)
		}
		if s.gpmAdminRoutesSource != "GPM_LOCAL_API_ADMIN_ROUTES-invalid-env-fail-closed" {
			t.Fatalf("gpmAdminRoutesSource=%q want invalid fail-closed source", s.gpmAdminRoutesSource)
		}
	})

	t.Run("overrides and timeout validation", func(t *testing.T) {
		tmpDir := t.TempDir()
		overrideScriptPath := filepath.Join(tmpDir, "easy_node.sh")
		if err := os.WriteFile(overrideScriptPath, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write override script: %v", err)
		}

		t.Setenv("LOCAL_CONTROL_API_ADDR", "0.0.0.0:9999")
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", " "+overrideScriptPath+" ")
		t.Setenv("LOCAL_CONTROL_API_RUNNER", " bash ")
		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "240")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UPDATE", "1")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "1")
		t.Setenv(allowInsecureHTTPEnv, "1")
		t.Setenv(maxCommandsEnv, "9")
		t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", " local-secret ")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "1")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "75")

		s := New()
		if s.addr != "0.0.0.0:9999" {
			t.Fatalf("addr=%q", s.addr)
		}
		if s.scriptPath != overrideScriptPath {
			t.Fatalf("scriptPath=%q want=%q", s.scriptPath, overrideScriptPath)
		}
		if s.commandRunner != "bash" {
			t.Fatalf("commandRunner=%q", s.commandRunner)
		}
		if s.commandTimeout != 240*time.Second {
			t.Fatalf("commandTimeout=%s", s.commandTimeout)
		}
		if s.maxConcurrentCmds != 9 {
			t.Fatalf("maxConcurrentCmds=%d want=9", s.maxConcurrentCmds)
		}
		if !s.allowUpdate {
			t.Fatalf("allowUpdate=%t want=true", s.allowUpdate)
		}
		if !s.allowUnauthLoopback {
			t.Fatalf("allowUnauthLoopback=%t want=true", s.allowUnauthLoopback)
		}
		if !s.allowInsecureHTTP {
			t.Fatalf("allowInsecureHTTP=%t want=true", s.allowInsecureHTTP)
		}
		if s.authToken != "local-secret" {
			t.Fatalf("authToken=%q want=%q", s.authToken, "local-secret")
		}
		if !s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=true", s.gpmAllowLegacyConnectOverride)
		}
		if s.gpmManifestRemoteRefreshIntvl != 75*time.Second {
			t.Fatalf("gpmManifestRemoteRefreshIntvl=%s want=1m15s", s.gpmManifestRemoteRefreshIntvl)
		}
		if s.gpmManifestRemoteRefreshSrc != "GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC" {
			t.Fatalf("gpmManifestRemoteRefreshSrc=%q want=GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", s.gpmManifestRemoteRefreshSrc)
		}

		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "4")
		s = New()
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("timeout <5 should fall back to default, got=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}

		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "bad")
		s = New()
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("invalid timeout should fall back to default, got=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}

		t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "not-bool")
		s = New()
		if s.allowUnauthLoopback {
			t.Fatalf("invalid LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK should default to false")
		}

		t.Setenv(maxCommandsEnv, "0")
		s = New()
		if s.maxConcurrentCmds != defaultMaxCommands {
			t.Fatalf("maxConcurrentCmds=%d want default %d for zero", s.maxConcurrentCmds, defaultMaxCommands)
		}

		t.Setenv(maxCommandsEnv, "bad")
		s = New()
		if s.maxConcurrentCmds != defaultMaxCommands {
			t.Fatalf("maxConcurrentCmds=%d want default %d for invalid value", s.maxConcurrentCmds, defaultMaxCommands)
		}

		t.Setenv(maxCommandsEnv, "1000")
		s = New()
		if s.maxConcurrentCmds != maxAllowedCommands {
			t.Fatalf("maxConcurrentCmds=%d want capped %d", s.maxConcurrentCmds, maxAllowedCommands)
		}

		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "bad")
		s = New()
		if s.gpmManifestRemoteRefreshIntvl != 5*time.Minute {
			t.Fatalf("invalid refresh interval should fall back to default, got=%s want=5m0s", s.gpmManifestRemoteRefreshIntvl)
		}
		if s.gpmManifestRemoteRefreshSrc != "default" {
			t.Fatalf("invalid refresh interval source=%q want=default", s.gpmManifestRemoteRefreshSrc)
		}
	})

	t.Run("tdpn alias sets manifest remote refresh interval", func(t *testing.T) {
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "42")

		s := New()
		if s.gpmManifestRemoteRefreshIntvl != 42*time.Second {
			t.Fatalf("gpmManifestRemoteRefreshIntvl=%s want=42s", s.gpmManifestRemoteRefreshIntvl)
		}
		if s.gpmManifestRemoteRefreshSrc != "TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC" {
			t.Fatalf(
				"gpmManifestRemoteRefreshSrc=%q want=TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC",
				s.gpmManifestRemoteRefreshSrc,
			)
		}
	})

	t.Run("tdpn aliases enable new auth verify policies", func(t *testing.T) {
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "1")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "1")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "1")

		s := New()
		if !s.gpmAuthVerifyRequireMetadata {
			t.Fatalf("gpmAuthVerifyRequireMetadata=%t want=true", s.gpmAuthVerifyRequireMetadata)
		}
		if !s.gpmAuthVerifyRequireWalletExt {
			t.Fatalf("gpmAuthVerifyRequireWalletExt=%t want=true", s.gpmAuthVerifyRequireWalletExt)
		}
		if s.gpmAuthVerifyMetadataSource != "TDPN_AUTH_VERIFY_REQUIRE_METADATA" {
			t.Fatalf("gpmAuthVerifyMetadataSource=%q want=TDPN_AUTH_VERIFY_REQUIRE_METADATA", s.gpmAuthVerifyMetadataSource)
		}
		if s.gpmAuthVerifyWalletExtSource != "TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE" {
			t.Fatalf("gpmAuthVerifyWalletExtSource=%q want=TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", s.gpmAuthVerifyWalletExtSource)
		}
		if !s.gpmAuthVerifyRequireCryptoProof {
			t.Fatalf("gpmAuthVerifyRequireCryptoProof=%t want=true", s.gpmAuthVerifyRequireCryptoProof)
		}
		if s.gpmAuthVerifyCryptoSource != "TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF" {
			t.Fatalf("gpmAuthVerifyCryptoSource=%q want=TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", s.gpmAuthVerifyCryptoSource)
		}
	})

	t.Run("tdpn aliases are tracked for runtime telemetry", func(t *testing.T) {
		t.Setenv("GPM_MAIN_DOMAIN", "")
		t.Setenv("TDPN_MAIN_DOMAIN", "https://legacy-main.example")
		t.Setenv("GPM_PRODUCTION_MODE", "")
		t.Setenv("TDPN_PRODUCTION_MODE", "1")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "1")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "1")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "1")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", "61")

		s := New()

		wantAliases := map[string]struct{}{
			"TDPN_MAIN_DOMAIN":                                    {},
			"TDPN_PRODUCTION_MODE":                                {},
			"TDPN_CONNECT_REQUIRE_SESSION":                        {},
			"TDPN_AUTH_VERIFY_REQUIRE_METADATA":                   {},
			"TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF":               {},
			"TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC": {},
		}
		if got, want := len(s.gpmLegacyEnvAliasesActive), len(wantAliases); got != want {
			t.Fatalf("gpmLegacyEnvAliasesActive len=%d want=%d aliases=%v", got, want, s.gpmLegacyEnvAliasesActive)
		}
		for _, alias := range s.gpmLegacyEnvAliasesActive {
			if _, ok := wantAliases[alias]; !ok {
				t.Fatalf("unexpected legacy alias tracked: %q all=%v", alias, s.gpmLegacyEnvAliasesActive)
			}
			delete(wantAliases, alias)
		}
		if len(wantAliases) != 0 {
			t.Fatalf("missing expected legacy aliases: %v all=%v", wantAliases, s.gpmLegacyEnvAliasesActive)
		}
		if got, want := len(s.gpmLegacyEnvAliasWarnings), 6; got != want {
			t.Fatalf("gpmLegacyEnvAliasWarnings len=%d want=%d warnings=%v", got, want, s.gpmLegacyEnvAliasWarnings)
		}
		for _, warning := range s.gpmLegacyEnvAliasWarnings {
			if !strings.Contains(warning, "is deprecated; migrate to GPM_") {
				t.Fatalf("unexpected warning format: %q", warning)
			}
		}
	})

	t.Run("production mode enforces secure connect and auth defaults when flags unset", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")

		s := New()
		if !s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=true", s.gpmConnectRequireSession)
		}
		if !s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=true", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "production-default" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=production-default",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
		}
		if !s.gpmLegacyConnectRequireTrustedManifestBootstrap {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrap=%t want=true",
				s.gpmLegacyConnectRequireTrustedManifestBootstrap,
			)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrapSource != "production-default" {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrapSource=%q want=production-default",
				s.gpmLegacyConnectRequireTrustedManifestBootstrapSource,
			)
		}
		if s.gpmConnectPolicyMode != "production" {
			t.Fatalf("gpmConnectPolicyMode=%q want=production", s.gpmConnectPolicyMode)
		}
		if s.gpmConnectPolicySource != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpmConnectPolicySource=%q want=GPM_PRODUCTION_MODE", s.gpmConnectPolicySource)
		}
		if s.gpmManifestTrustPolicyMode != "production" {
			t.Fatalf("gpmManifestTrustPolicyMode=%q want=production", s.gpmManifestTrustPolicyMode)
		}
		if s.gpmManifestTrustPolicySource != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpmManifestTrustPolicySource=%q want=GPM_PRODUCTION_MODE", s.gpmManifestTrustPolicySource)
		}
		if !s.gpmManifestRequireHTTPS {
			t.Fatalf("gpmManifestRequireHTTPS=%t want=true", s.gpmManifestRequireHTTPS)
		}
		if !s.gpmManifestRequireSignature {
			t.Fatalf("gpmManifestRequireSignature=%t want=true", s.gpmManifestRequireSignature)
		}
		if s.gpmManifestRequireHTTPSSource != "production-default" {
			t.Fatalf("gpmManifestRequireHTTPSSource=%q want=production-default", s.gpmManifestRequireHTTPSSource)
		}
		if s.gpmManifestRequireSigSource != "production-default" {
			t.Fatalf("gpmManifestRequireSigSource=%q want=production-default", s.gpmManifestRequireSigSource)
		}
		if s.gpmManifestRefreshFailureMaxCacheAge != 15*time.Minute {
			t.Fatalf("gpmManifestRefreshFailureMaxCacheAge=%s want=15m0s", s.gpmManifestRefreshFailureMaxCacheAge)
		}
		if s.gpmManifestRefreshFailureMaxCacheAgeSrc != "production-default" {
			t.Fatalf(
				"gpmManifestRefreshFailureMaxCacheAgeSrc=%q want=production-default",
				s.gpmManifestRefreshFailureMaxCacheAgeSrc,
			)
		}
		if !s.gpmAuthVerifyRequireMetadata {
			t.Fatalf("gpmAuthVerifyRequireMetadata=%t want=true", s.gpmAuthVerifyRequireMetadata)
		}
		if !s.gpmAuthVerifyRequireWalletExt {
			t.Fatalf("gpmAuthVerifyRequireWalletExt=%t want=true", s.gpmAuthVerifyRequireWalletExt)
		}
		if !s.gpmAuthVerifyRequireCommand {
			t.Fatalf("gpmAuthVerifyRequireCommand=%t want=true", s.gpmAuthVerifyRequireCommand)
		}
		if s.gpmAuthVerifyRequireCmdSource != "production-default" {
			t.Fatalf("gpmAuthVerifyRequireCmdSource=%q want=production-default", s.gpmAuthVerifyRequireCmdSource)
		}
		if s.gpmAuthVerifyPolicyMode != "production" {
			t.Fatalf("gpmAuthVerifyPolicyMode=%q want=production", s.gpmAuthVerifyPolicyMode)
		}
		if s.gpmAuthVerifyPolicySource != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpmAuthVerifyPolicySource=%q want=GPM_PRODUCTION_MODE", s.gpmAuthVerifyPolicySource)
		}
		if s.gpmAuthVerifyMetadataSource != "production-default" {
			t.Fatalf("gpmAuthVerifyMetadataSource=%q want=production-default", s.gpmAuthVerifyMetadataSource)
		}
		if s.gpmAuthVerifyWalletExtSource != "production-default" {
			t.Fatalf("gpmAuthVerifyWalletExtSource=%q want=production-default", s.gpmAuthVerifyWalletExtSource)
		}
		if !s.gpmAuthVerifyRequireCryptoProof {
			t.Fatalf("gpmAuthVerifyRequireCryptoProof=%t want=true", s.gpmAuthVerifyRequireCryptoProof)
		}
		if s.gpmAuthVerifyCryptoSource != "production-default" {
			t.Fatalf("gpmAuthVerifyCryptoSource=%q want=production-default", s.gpmAuthVerifyCryptoSource)
		}
	})

	t.Run("production mode fails closed when GPM_PRODUCTION_MODE env is invalid", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "definitely-not-bool")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")

		s := New()
		if !s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=true", s.gpmConnectRequireSession)
		}
		if s.gpmConnectPolicyMode != "production" {
			t.Fatalf("gpmConnectPolicyMode=%q want=production", s.gpmConnectPolicyMode)
		}
		if s.gpmConnectPolicySource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmConnectPolicySource=%q want=production-invalid-env-fail-closed", s.gpmConnectPolicySource)
		}
		if s.gpmManifestTrustPolicyMode != "production" {
			t.Fatalf("gpmManifestTrustPolicyMode=%q want=production", s.gpmManifestTrustPolicyMode)
		}
		if s.gpmManifestTrustPolicySource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmManifestTrustPolicySource=%q want=production-invalid-env-fail-closed", s.gpmManifestTrustPolicySource)
		}
		if s.gpmAuthVerifyPolicyMode != "production" {
			t.Fatalf("gpmAuthVerifyPolicyMode=%q want=production", s.gpmAuthVerifyPolicyMode)
		}
		if s.gpmAuthVerifyPolicySource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmAuthVerifyPolicySource=%q want=production-invalid-env-fail-closed", s.gpmAuthVerifyPolicySource)
		}
		if s.gpmManifestRefreshFailureMaxCacheAge != 15*time.Minute {
			t.Fatalf("gpmManifestRefreshFailureMaxCacheAge=%s want=15m0s", s.gpmManifestRefreshFailureMaxCacheAge)
		}
		if s.gpmManifestRefreshFailureMaxCacheAgeSrc != "production-default" {
			t.Fatalf(
				"gpmManifestRefreshFailureMaxCacheAgeSrc=%q want=production-default",
				s.gpmManifestRefreshFailureMaxCacheAgeSrc,
			)
		}
	})

	t.Run("production mode fails closed when manifest refresh-failure cache ceiling is disabled or invalid", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "0")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "")

		s := New()
		if s.gpmManifestRefreshFailureMaxCacheAge != 15*time.Minute {
			t.Fatalf("gpmManifestRefreshFailureMaxCacheAge=%s want=15m0s", s.gpmManifestRefreshFailureMaxCacheAge)
		}
		if s.gpmManifestRefreshFailureMaxCacheAgeSrc != "production-refresh-failure-cache-fail-closed" {
			t.Fatalf(
				"gpmManifestRefreshFailureMaxCacheAgeSrc=%q want=production-refresh-failure-cache-fail-closed",
				s.gpmManifestRefreshFailureMaxCacheAgeSrc,
			)
		}

		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", "not-a-duration")
		s = New()
		if s.gpmManifestRefreshFailureMaxCacheAge != 15*time.Minute {
			t.Fatalf("invalid env gpmManifestRefreshFailureMaxCacheAge=%s want=15m0s", s.gpmManifestRefreshFailureMaxCacheAge)
		}
		if s.gpmManifestRefreshFailureMaxCacheAgeSrc != "production-invalid-env-fail-closed" {
			t.Fatalf(
				"invalid env gpmManifestRefreshFailureMaxCacheAgeSrc=%q want=production-invalid-env-fail-closed",
				s.gpmManifestRefreshFailureMaxCacheAgeSrc,
			)
		}
	})

	t.Run("production mode enforces manifest trust even when flags are explicitly false", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "0")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "false")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")

		s := New()
		if !s.gpmManifestRequireHTTPS {
			t.Fatalf("gpmManifestRequireHTTPS=%t want=true", s.gpmManifestRequireHTTPS)
		}
		if s.gpmManifestRequireHTTPSSource != "production-enforced" {
			t.Fatalf("gpmManifestRequireHTTPSSource=%q want=production-enforced", s.gpmManifestRequireHTTPSSource)
		}
		if !s.gpmManifestRequireSignature {
			t.Fatalf("gpmManifestRequireSignature=%t want=true", s.gpmManifestRequireSignature)
		}
		if s.gpmManifestRequireSigSource != "production-enforced" {
			t.Fatalf("gpmManifestRequireSigSource=%q want=production-enforced", s.gpmManifestRequireSigSource)
		}
	})

	t.Run("production mode fails closed when security booleans are invalid", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "invalid")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "invalid")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "invalid")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "invalid")
		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "invalid")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "invalid")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "invalid")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "invalid")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "invalid")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")

		s := New()
		if !s.gpmManifestRequireHTTPS {
			t.Fatalf("gpmManifestRequireHTTPS=%t want=true", s.gpmManifestRequireHTTPS)
		}
		if s.gpmManifestRequireHTTPSSource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmManifestRequireHTTPSSource=%q want=production-invalid-env-fail-closed", s.gpmManifestRequireHTTPSSource)
		}
		if !s.gpmManifestRequireSignature {
			t.Fatalf("gpmManifestRequireSignature=%t want=true", s.gpmManifestRequireSignature)
		}
		if s.gpmManifestRequireSigSource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmManifestRequireSigSource=%q want=production-invalid-env-fail-closed", s.gpmManifestRequireSigSource)
		}
		if !s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=true", s.gpmConnectRequireSession)
		}
		if !s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=true", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "production-invalid-env-fail-closed" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=production-invalid-env-fail-closed",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
		}
		if !s.gpmAuthVerifyRequireCommand {
			t.Fatalf("gpmAuthVerifyRequireCommand=%t want=true", s.gpmAuthVerifyRequireCommand)
		}
		if s.gpmAuthVerifyRequireCmdSource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmAuthVerifyRequireCmdSource=%q want=production-invalid-env-fail-closed", s.gpmAuthVerifyRequireCmdSource)
		}
		if !s.gpmAuthVerifyRequireMetadata {
			t.Fatalf("gpmAuthVerifyRequireMetadata=%t want=true", s.gpmAuthVerifyRequireMetadata)
		}
		if s.gpmAuthVerifyMetadataSource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmAuthVerifyMetadataSource=%q want=production-invalid-env-fail-closed", s.gpmAuthVerifyMetadataSource)
		}
		if !s.gpmAuthVerifyRequireWalletExt {
			t.Fatalf("gpmAuthVerifyRequireWalletExt=%t want=true", s.gpmAuthVerifyRequireWalletExt)
		}
		if s.gpmAuthVerifyWalletExtSource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmAuthVerifyWalletExtSource=%q want=production-invalid-env-fail-closed", s.gpmAuthVerifyWalletExtSource)
		}
		if !s.gpmAuthVerifyRequireCryptoProof {
			t.Fatalf("gpmAuthVerifyRequireCryptoProof=%t want=true", s.gpmAuthVerifyRequireCryptoProof)
		}
		if s.gpmAuthVerifyCryptoSource != "production-invalid-env-fail-closed" {
			t.Fatalf("gpmAuthVerifyCryptoSource=%q want=production-invalid-env-fail-closed", s.gpmAuthVerifyCryptoSource)
		}
	})

	t.Run("production mode fails closed when legacy trusted-manifest binding env is invalid", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "not-a-bool")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")

		s := New()
		if !s.gpmLegacyConnectRequireTrustedManifestBootstrap {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrap=%t want=true",
				s.gpmLegacyConnectRequireTrustedManifestBootstrap,
			)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrapSource != "production-invalid-env-fail-closed" {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrapSource=%q want=production-invalid-env-fail-closed",
				s.gpmLegacyConnectRequireTrustedManifestBootstrapSource,
			)
		}
	})

	t.Run("non-production honors explicit false for legacy trusted-manifest binding env", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "0")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")

		s := New()
		if s.gpmLegacyConnectRequireTrustedManifestBootstrap {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrap=%t want=false",
				s.gpmLegacyConnectRequireTrustedManifestBootstrap,
			)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrapSource != "GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP" {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrapSource=%q want=GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP",
				s.gpmLegacyConnectRequireTrustedManifestBootstrapSource,
			)
		}
	})

	t.Run("production mode enforces connect guardrails even when legacy envs try to relax them", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "0")
		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "0")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "1")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "0")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "0")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "0")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "0")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "0")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "0")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "1")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")

		s := New()
		if !s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=true", s.gpmConnectRequireSession)
		}
		if s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=false", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "GPM_OPERATOR_APPROVAL_REQUIRE_SESSION" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=GPM_OPERATOR_APPROVAL_REQUIRE_SESSION",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
		}
		if !s.gpmLegacyConnectRequireTrustedManifestBootstrap {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrap=%t want=true",
				s.gpmLegacyConnectRequireTrustedManifestBootstrap,
			)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrapSource != "production-enforced" {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrapSource=%q want=production-enforced",
				s.gpmLegacyConnectRequireTrustedManifestBootstrapSource,
			)
		}
		if s.gpmConnectPolicyMode != "production" {
			t.Fatalf("gpmConnectPolicyMode=%q want=production", s.gpmConnectPolicyMode)
		}
		if s.gpmConnectPolicySource != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpmConnectPolicySource=%q want=GPM_PRODUCTION_MODE", s.gpmConnectPolicySource)
		}
		if s.gpmManifestTrustPolicyMode != "production" {
			t.Fatalf("gpmManifestTrustPolicyMode=%q want=production", s.gpmManifestTrustPolicyMode)
		}
		if s.gpmManifestTrustPolicySource != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpmManifestTrustPolicySource=%q want=GPM_PRODUCTION_MODE", s.gpmManifestTrustPolicySource)
		}
		if !s.gpmManifestRequireHTTPS {
			t.Fatalf("gpmManifestRequireHTTPS=%t want=true", s.gpmManifestRequireHTTPS)
		}
		if !s.gpmManifestRequireSignature {
			t.Fatalf("gpmManifestRequireSignature=%t want=true", s.gpmManifestRequireSignature)
		}
		if s.gpmManifestRequireHTTPSSource != "production-enforced" {
			t.Fatalf("gpmManifestRequireHTTPSSource=%q want=production-enforced", s.gpmManifestRequireHTTPSSource)
		}
		if s.gpmManifestRequireSigSource != "production-enforced" {
			t.Fatalf("gpmManifestRequireSigSource=%q want=production-enforced", s.gpmManifestRequireSigSource)
		}
		if s.gpmAuthVerifyRequireMetadata {
			t.Fatalf("gpmAuthVerifyRequireMetadata=%t want=false", s.gpmAuthVerifyRequireMetadata)
		}
		if s.gpmAuthVerifyRequireWalletExt {
			t.Fatalf("gpmAuthVerifyRequireWalletExt=%t want=false", s.gpmAuthVerifyRequireWalletExt)
		}
		if s.gpmAuthVerifyRequireCommand {
			t.Fatalf("gpmAuthVerifyRequireCommand=%t want=false", s.gpmAuthVerifyRequireCommand)
		}
		if s.gpmAuthVerifyRequireCmdSource != "GPM_AUTH_VERIFY_REQUIRE_COMMAND" {
			t.Fatalf("gpmAuthVerifyRequireCmdSource=%q want=GPM_AUTH_VERIFY_REQUIRE_COMMAND", s.gpmAuthVerifyRequireCmdSource)
		}
		if s.gpmAuthVerifyPolicyMode != "production" {
			t.Fatalf("gpmAuthVerifyPolicyMode=%q want=production", s.gpmAuthVerifyPolicyMode)
		}
		if s.gpmAuthVerifyPolicySource != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpmAuthVerifyPolicySource=%q want=GPM_PRODUCTION_MODE", s.gpmAuthVerifyPolicySource)
		}
		if s.gpmAuthVerifyMetadataSource != "GPM_AUTH_VERIFY_REQUIRE_METADATA" {
			t.Fatalf("gpmAuthVerifyMetadataSource=%q want=GPM_AUTH_VERIFY_REQUIRE_METADATA", s.gpmAuthVerifyMetadataSource)
		}
		if s.gpmAuthVerifyWalletExtSource != "TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE" {
			t.Fatalf("gpmAuthVerifyWalletExtSource=%q want=TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", s.gpmAuthVerifyWalletExtSource)
		}
		if !s.gpmAuthVerifyRequireCryptoProof {
			t.Fatalf("gpmAuthVerifyRequireCryptoProof=%t want=true", s.gpmAuthVerifyRequireCryptoProof)
		}
		if s.gpmAuthVerifyCryptoSource != "GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF" {
			t.Fatalf("gpmAuthVerifyCryptoSource=%q want=GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", s.gpmAuthVerifyCryptoSource)
		}
	})

	t.Run("production mode enforces connect guardrails for TDPN legacy aliases too", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "0")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "1")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "0")

		s := New()
		if !s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=true", s.gpmConnectRequireSession)
		}
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
		}
		if !s.gpmLegacyConnectRequireTrustedManifestBootstrap {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrap=%t want=true",
				s.gpmLegacyConnectRequireTrustedManifestBootstrap,
			)
		}
		if s.gpmLegacyConnectRequireTrustedManifestBootstrapSource != "production-enforced" {
			t.Fatalf(
				"gpmLegacyConnectRequireTrustedManifestBootstrapSource=%q want=production-enforced",
				s.gpmLegacyConnectRequireTrustedManifestBootstrapSource,
			)
		}
	})

	t.Run("approval token env aliases honor new-key precedence", func(t *testing.T) {
		t.Setenv("GPM_APPROVAL_ADMIN_TOKEN", "")
		t.Setenv("TDPN_APPROVAL_ADMIN_TOKEN", "")
		t.Setenv("GPM_OPERATOR_APPROVAL_TOKEN", "")
		t.Setenv("TDPN_OPERATOR_APPROVAL_TOKEN", "")

		s := New()
		if s.gpmApprovalToken != "" {
			t.Fatalf("gpmApprovalToken=%q want empty", s.gpmApprovalToken)
		}

		t.Setenv("GPM_OPERATOR_APPROVAL_TOKEN", "legacy-operator-token")
		s = New()
		if s.gpmApprovalToken != "legacy-operator-token" {
			t.Fatalf("gpmApprovalToken=%q want legacy operator token", s.gpmApprovalToken)
		}

		t.Setenv("GPM_APPROVAL_ADMIN_TOKEN", "new-admin-token")
		s = New()
		if s.gpmApprovalToken != "new-admin-token" {
			t.Fatalf("gpmApprovalToken=%q want new admin token precedence", s.gpmApprovalToken)
		}

		t.Setenv("GPM_APPROVAL_ADMIN_TOKEN", "")
		t.Setenv("TDPN_APPROVAL_ADMIN_TOKEN", "tdpn-admin-token")
		s = New()
		if s.gpmApprovalToken != "tdpn-admin-token" {
			t.Fatalf("gpmApprovalToken=%q want TDPN admin alias", s.gpmApprovalToken)
		}
	})

	t.Run("operator approval require session env aliases honor new-key precedence", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "")

		s := New()
		if s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=false", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "default" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=default",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}

		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "1")
		s = New()
		if !s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=true", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}

		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "0")
		s = New()
		if s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=false", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "GPM_OPERATOR_APPROVAL_REQUIRE_SESSION" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=GPM_OPERATOR_APPROVAL_REQUIRE_SESSION",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}

		t.Setenv("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION", "")
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		s = New()
		if !s.gpmOperatorApprovalRequireSession {
			t.Fatalf("gpmOperatorApprovalRequireSession=%t want=true", s.gpmOperatorApprovalRequireSession)
		}
		if s.gpmOperatorApprovalRequireSessionSource != "production-default" {
			t.Fatalf(
				"gpmOperatorApprovalRequireSessionSource=%q want=production-default",
				s.gpmOperatorApprovalRequireSessionSource,
			)
		}
	})

	t.Run("invalid script path fails safe", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", filepath.Join(t.TempDir(), "does-not-exist.sh"))
		s := New()
		if s.scriptPath != "" {
			t.Fatalf("scriptPath=%q want empty when configured script path is invalid", s.scriptPath)
		}
	})
}

func TestLocalAPIPublicModeDoesNotRegisterAdminRoutes(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmAdminRoutesEnabled = false
	handler := svc.routes()

	adminRoutes := []string{
		"/v1/set_profile",
		"/v1/update",
		"/v1/service/status",
		"/v1/service/start",
		"/v1/service/stop",
		"/v1/service/restart",
		"/v1/get_diagnostics",
		"/v1/gpm/service/start",
		"/v1/gpm/service/stop",
		"/v1/gpm/service/restart",
		"/v1/gpm/audit/recent",
		"/v1/gpm/gaps/summary",
		"/v1/gpm/admin/contributions/list",
		"/v1/gpm/admin/rewards/review",
		"/v1/gpm/admin/rewards/hold",
		"/v1/gpm/admin/rewards/finalize",
		"/v1/gpm/onboarding/server/status",
		"/v1/gpm/onboarding/operator/apply",
		"/v1/gpm/onboarding/operator/status",
		"/v1/gpm/onboarding/operator/list",
		"/v1/gpm/onboarding/operator/approve",
	}
	for _, route := range adminRoutes {
		if got := callRouteStatus(t, handler, http.MethodGet, route); got != http.StatusNotFound {
			t.Fatalf("public daemon route %s status=%d want=404", route, got)
		}
	}

	publicRoutes := []string{
		"/v1/health",
		"/v1/config",
		"/v1/connect",
		"/v1/disconnect",
		"/v1/gpm/bootstrap/manifest",
		"/v1/gpm/auth/challenge",
		"/v1/gpm/session",
		"/v1/gpm/onboarding/client/status",
		"/v1/gpm/contribution/status",
		"/v1/gpm/rewards/history",
		"/v1/gpm/onboarding/overview",
	}
	for _, route := range publicRoutes {
		if got := callRouteStatus(t, handler, http.MethodGet, route); got == http.StatusNotFound {
			t.Fatalf("public daemon route %s status=404 want registered", route)
		}
	}
}

func TestLocalAPIAdminConsoleEnvDoesNotRegisterAdminRoutes(t *testing.T) {
	t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "")
	t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
	t.Setenv("GPM_ADMIN_CONSOLE", "1")
	t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "1")
	t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "1")

	svc := New()
	handler := svc.routes()

	if got := callRouteStatus(t, handler, http.MethodGet, "/v1/gpm/admin/contributions/list"); got != http.StatusNotFound {
		t.Fatalf("admin console ui env route status=%d want=404", got)
	}
	if got := callRouteStatus(t, handler, http.MethodGet, "/v1/service/status"); got != http.StatusNotFound {
		t.Fatalf("legacy admin service route status=%d want=404", got)
	}
}

func TestLocalAPIExplicitAdminRoutesEnvRegistersAdminRoutes(t *testing.T) {
	t.Setenv("GPM_LOCAL_API_ADMIN_ROUTES", "1")
	t.Setenv("TDPN_LOCAL_API_ADMIN_ROUTES", "")
	t.Setenv("GPM_ADMIN_CONSOLE", "")
	t.Setenv("GPM_DESKTOP_ADMIN_CONSOLE", "")
	t.Setenv("TDPN_DESKTOP_ADMIN_CONSOLE", "")

	svc := New()
	handler := svc.routes()

	if got := callRouteStatus(t, handler, http.MethodGet, "/v1/gpm/admin/contributions/list"); got == http.StatusNotFound {
		t.Fatalf("explicit admin route env status=404 want registered")
	}
	if got := callRouteStatus(t, handler, http.MethodGet, "/v1/service/status"); got == http.StatusNotFound {
		t.Fatalf("explicit legacy admin service route status=404 want registered")
	}
	if !svc.gpmOperatorApprovalRequireSession {
		t.Fatalf("admin routes should default operator approval to admin session auth")
	}
	if svc.gpmOperatorApprovalRequireSessionSource != "admin-routes-default" {
		t.Fatalf("operator approval source=%q want admin-routes-default", svc.gpmOperatorApprovalRequireSessionSource)
	}
}

func TestLocalAPIAdminConsoleModeRegistersAdminRoutes(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmAdminRoutesEnabled = true
	handler := svc.routes()

	adminRoutes := []string{
		"/v1/set_profile",
		"/v1/update",
		"/v1/service/status",
		"/v1/service/start",
		"/v1/service/stop",
		"/v1/service/restart",
		"/v1/get_diagnostics",
		"/v1/gpm/service/start",
		"/v1/gpm/service/stop",
		"/v1/gpm/service/restart",
		"/v1/gpm/audit/recent",
		"/v1/gpm/gaps/summary",
		"/v1/gpm/admin/contributions/list",
		"/v1/gpm/admin/rewards/review",
		"/v1/gpm/admin/rewards/hold",
		"/v1/gpm/admin/rewards/finalize",
		"/v1/gpm/onboarding/server/status",
		"/v1/gpm/onboarding/operator/apply",
		"/v1/gpm/onboarding/operator/status",
		"/v1/gpm/onboarding/operator/list",
		"/v1/gpm/onboarding/operator/approve",
	}
	for _, route := range adminRoutes {
		if got := callRouteStatus(t, handler, http.MethodGet, route); got == http.StatusNotFound {
			t.Fatalf("admin daemon route %s status=404 want registered", route)
		}
	}
}

func TestLocalAPICORSPreflight(t *testing.T) {
	t.Run("auth configured allows loopback portal preflight from another port", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.authToken = "local-api-token"
		handler := svc.routes()
		req := httptest.NewRequest(http.MethodOptions, "/v1/gpm/auth/challenge", nil)
		req.Header.Set("Origin", "http://127.0.0.1:5173")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status=%d want=204 body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:5173" {
			t.Fatalf("allow-origin=%q", got)
		}
	})

	t.Run("auth configured rejects dns rebinding loopback origin", func(t *testing.T) {
		originalLookup := lookupIPAddr
		t.Cleanup(func() {
			lookupIPAddr = originalLookup
		})
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}

		svc, _ := newFakeService(t, false)
		svc.authToken = "local-api-token"
		handler := svc.routes()
		req := httptest.NewRequest(http.MethodOptions, "/v1/gpm/auth/challenge", nil)
		req.Header.Set("Origin", "http://rebind.example:5173")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("unauth loopback rejects cross-port preflight", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = true
		handler := svc.routes()
		req := httptest.NewRequest(http.MethodOptions, "/v1/gpm/auth/challenge", nil)
		req.Header.Set("Origin", "http://127.0.0.1:5173")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestConfigReportsDaemonAdminRouteSurface(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmAdminRoutesEnabled = false
	svc.gpmAdminRoutesSource = "default"
	code, payload := callJSONHandler(t, svc.handleConfig, http.MethodGet, "/v1/config", "")
	if code != http.StatusOK {
		t.Fatalf("config code=%d payload=%v", code, payload)
	}
	cfg := payload["config"].(map[string]any)
	if mode, _ := cfg["gpm_daemon_surface_mode"].(string); mode != "public_app" {
		t.Fatalf("gpm_daemon_surface_mode=%q want public_app payload=%v", mode, payload)
	}
	if enabled, _ := cfg["gpm_admin_routes_enabled"].(bool); enabled {
		t.Fatalf("gpm_admin_routes_enabled=%v want=false payload=%v", enabled, payload)
	}
	if source, _ := cfg["gpm_admin_routes_policy_source"].(string); source != "default" {
		t.Fatalf("gpm_admin_routes_policy_source=%q want default payload=%v", source, payload)
	}

	svc.gpmAdminRoutesEnabled = true
	svc.gpmAdminRoutesSource = "GPM_LOCAL_API_ADMIN_ROUTES"
	code, payload = callJSONHandler(t, svc.handleConfig, http.MethodGet, "/v1/config", "")
	if code != http.StatusOK {
		t.Fatalf("config(admin) code=%d payload=%v", code, payload)
	}
	cfg = payload["config"].(map[string]any)
	if mode, _ := cfg["gpm_daemon_surface_mode"].(string); mode != "admin_console" {
		t.Fatalf("gpm_daemon_surface_mode=%q want admin_console payload=%v", mode, payload)
	}
	if enabled, _ := cfg["gpm_admin_routes_enabled"].(bool); !enabled {
		t.Fatalf("gpm_admin_routes_enabled=%v want=true payload=%v", enabled, payload)
	}
	if source, _ := cfg["gpm_admin_routes_policy_source"].(string); source != "GPM_LOCAL_API_ADMIN_ROUTES" {
		t.Fatalf("gpm_admin_routes_policy_source=%q want GPM_LOCAL_API_ADMIN_ROUTES payload=%v", source, payload)
	}
}

func TestRunRejectsInsecureNonLoopbackBindByDefault(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.addr = "0.0.0.0:8095"
	svc.allowInsecureHTTP = false

	err := svc.Run(context.Background())
	if err == nil {
		t.Fatal("expected non-loopback insecure bind to be rejected")
	}
	if !strings.Contains(err.Error(), allowInsecureHTTPEnv) {
		t.Fatalf("expected error to mention %s, got %v", allowInsecureHTTPEnv, err)
	}
}

func TestRunRejectsWeakRemoteAuthTokensWhenInsecureHTTPAllowed(t *testing.T) {
	tests := []struct {
		name      string
		authToken string
		wantError string
	}{
		{name: "empty", authToken: "", wantError: "must be set"},
		{name: "token", authToken: "token", wantError: "weak/default"},
		{name: "default-token", authToken: "default-token", wantError: "weak/default"},
		{name: "secret-token", authToken: "secret-token", wantError: "weak/default"},
		{name: "change-me", authToken: "change-me", wantError: "weak/default"},
		{name: "short", authToken: "short-random-token-123", wantError: "at least"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.addr = "0.0.0.0:8095"
			svc.allowInsecureHTTP = true
			svc.authToken = tc.authToken

			err := svc.Run(context.Background())
			if err == nil {
				t.Fatal("expected weak remote auth token to be rejected")
			}
			errText := err.Error()
			if !strings.Contains(errText, "refusing insecure non-loopback local api bind") {
				t.Fatalf("expected non-loopback bind rejection, got %v", err)
			}
			if !strings.Contains(errText, authTokenEnv) {
				t.Fatalf("expected error to mention %s, got %v", authTokenEnv, err)
			}
			if !strings.Contains(errText, tc.wantError) {
				t.Fatalf("expected error to contain %q, got %v", tc.wantError, err)
			}
		})
	}
}

func TestResolveControlScriptPathWithLookup(t *testing.T) {
	origEval := evalSymlinksPath
	t.Cleanup(func() {
		evalSymlinksPath = origEval
	})

	t.Run("anchors default path to executable directory", func(t *testing.T) {
		evalSymlinksPath = func(path string) (string, error) { return path, nil }
		execPath := "/opt/tdpn/bin/localapi"
		want := "/opt/tdpn/bin/scripts/easy_node.sh"
		if runtime.GOOS == "windows" {
			execPath = `C:\opt\tdpn\bin\localapi`
			want = `C:\opt\tdpn\bin\scripts\easy_node.sh`
		}
		got, err := resolveControlScriptPathWithLookup(
			"",
			func() (string, error) { return execPath, nil },
			func(path string) (os.FileInfo, error) {
				if path != want {
					return nil, os.ErrNotExist
				}
				return fakeFileInfo{name: "easy_node.sh", mode: 0o755}, nil
			},
		)
		if err != nil {
			t.Fatalf("resolve default script path error: %v", err)
		}
		if got != want {
			t.Fatalf("got=%q want=%q", got, want)
		}
	})

	t.Run("rejects relative path escaping executable directory", func(t *testing.T) {
		evalSymlinksPath = func(path string) (string, error) { return path, nil }
		execPath := "/opt/tdpn/bin/localapi"
		if runtime.GOOS == "windows" {
			execPath = `C:\opt\tdpn\bin\localapi`
		}
		_, err := resolveControlScriptPathWithLookup(
			"../outside.sh",
			func() (string, error) { return execPath, nil },
			func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		)
		if err == nil {
			t.Fatalf("expected escaping path to fail")
		}
	})

	t.Run("requires an existing non-directory target", func(t *testing.T) {
		evalSymlinksPath = func(path string) (string, error) { return path, nil }
		scriptPath := "/opt/tdpn/scripts/easy_node.sh"
		scriptDirPath := "/opt/tdpn/scripts"
		if runtime.GOOS == "windows" {
			scriptPath = `C:\opt\tdpn\scripts\easy_node.sh`
			scriptDirPath = `C:\opt\tdpn\scripts`
		}
		_, err := resolveControlScriptPathWithLookup(
			scriptPath,
			nil,
			func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		)
		if err == nil {
			t.Fatalf("expected missing script path to fail")
		}

		_, err = resolveControlScriptPathWithLookup(
			scriptDirPath,
			nil,
			func(string) (os.FileInfo, error) {
				return fakeFileInfo{name: "scripts", mode: os.ModeDir | 0o755}, nil
			},
		)
		if err == nil {
			t.Fatalf("expected directory script path to fail")
		}
	})

	t.Run("rejects symlink target escaping executable directory", func(t *testing.T) {
		evalSymlinksPath = filepath.EvalSymlinks
		root := t.TempDir()
		execDir := filepath.Join(root, "bin")
		scriptDir := filepath.Join(execDir, "scripts")
		outsidePath := filepath.Join(root, "outside.sh")
		if err := os.MkdirAll(scriptDir, 0o755); err != nil {
			t.Fatalf("mkdir script dir: %v", err)
		}
		if err := os.WriteFile(outsidePath, []byte("#!/usr/bin/env bash\n"), 0o755); err != nil {
			t.Fatalf("write outside script: %v", err)
		}
		linkPath := filepath.Join(scriptDir, "easy_node.sh")
		if err := os.Symlink(outsidePath, linkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		execPath := filepath.Join(execDir, "localapi")
		got, err := resolveControlScriptPathWithLookup("", func() (string, error) { return execPath, nil }, os.Stat)
		if err == nil {
			t.Fatalf("expected symlink escape to fail, got path=%q", got)
		}
		if !strings.Contains(err.Error(), "resolves outside executable directory") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildLifecycleCommandWithPlatform(t *testing.T) {
	t.Run("parses command into binary and args", func(t *testing.T) {
		cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform("systemctl restart tdpn-entry", runtime.GOOS)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if cmdName != "systemctl" {
			t.Fatalf("cmdName=%q want=systemctl", cmdName)
		}
		want := []string{"restart", "tdpn-entry"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("supports quoted args", func(t *testing.T) {
		cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform(`echo "service running"`, runtime.GOOS)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if cmdName != "echo" {
			t.Fatalf("cmdName=%q want=echo", cmdName)
		}
		want := []string{"service running"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("rejects implicit shell control operators", func(t *testing.T) {
		_, _, err := buildLifecycleCommandWithPlatform("echo bad && exit 1", runtime.GOOS)
		if err == nil {
			t.Fatalf("expected command with shell control operators to be rejected")
		}
		if !strings.Contains(err.Error(), "shell control operators") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allows explicit shell binary invocation", func(t *testing.T) {
		cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform(`bash -lc "echo ok && exit 0"`, runtime.GOOS)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q want=bash", cmdName)
		}
		want := []string{"-lc", "echo ok && exit 0"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})
}

func TestBuildEasyNodeCommandWithPlatform(t *testing.T) {
	t.Run("linux defaults to direct script execution", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform("./scripts/easy_node.sh", []string{"client-vpn-status", "--show-json", "1"}, "linux", "")
		if cmdName != "./scripts/easy_node.sh" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{"client-vpn-status", "--show-json", "1"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("explicit runner prefixes script path", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform("./scripts/easy_node.sh", []string{"client-vpn-status"}, "linux", "bash")
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{"./scripts/easy_node.sh", "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows ps1 defaults to powershell", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform(`C:\tdpn\easy_node.ps1`, []string{"client-vpn-status"}, "windows", "")
		if cmdName != "powershell" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		wantPrefix := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", `C:\tdpn\easy_node.ps1`}
		if strings.Join(cmdArgs[:len(wantPrefix)], "\t") != strings.Join(wantPrefix, "\t") {
			t.Fatalf("cmdArgs prefix=%v wantPrefix=%v", cmdArgs, wantPrefix)
		}
		if cmdArgs[len(cmdArgs)-1] != "client-vpn-status" {
			t.Fatalf("cmdArgs tail=%v", cmdArgs)
		}
	})

	t.Run("windows sh defaults to bash when no git-bash candidate is available", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(string) string { return "" },
			func(string) bool { return false },
		)
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows sh prefers git-bash candidates by default", func(t *testing.T) {
		gitBashPath := `C:\Program Files\Git\bin\bash.exe`
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(string) string { return "" },
			func(path string) bool { return path == gitBashPath },
		)
		if cmdName != gitBashPath {
			t.Fatalf("cmdName=%q want=%q", cmdName, gitBashPath)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows sh honors explicit git-bash path override", func(t *testing.T) {
		override := `D:\portable\git\bin\bash.exe`
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(name string) string {
				if name == "LOCAL_CONTROL_API_GIT_BASH_PATH" {
					return override
				}
				return ""
			},
			func(string) bool { return false },
		)
		if cmdName != override {
			t.Fatalf("cmdName=%q want=%q", cmdName, override)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows sh can disable git-bash preference", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(name string) string {
				if name == "LOCAL_CONTROL_API_PREFER_GIT_BASH" {
					return "0"
				}
				return ""
			},
			func(string) bool { return true },
		)
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q want=bash", cmdName)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})
}

func TestHandleConnectDefaults2Hop(t *testing.T) {
	svc, logPath := newFakeService(t, false)

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"bootstrap_directory":"https://dir.example:8081",
		"invite_key":"inv-test-2hop"
	}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["profile"].(string); got != "2hop" {
		t.Fatalf("profile=%q want=2hop", got)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 3 {
		t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
	}
	if cmds[0][0] != "client-vpn-preflight" || cmds[1][0] != "client-vpn-up" || cmds[2][0] != "client-vpn-status" {
		t.Fatalf("unexpected command order: %v", cmds)
	}

	mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir.example:8081")
	mustFlagValue(t, cmds[0], "--discovery-wait-sec", "20")
	mustFlagValue(t, cmds[0], "--path-profile", "2hop")
	mustFlagValue(t, cmds[0], "--prod-profile", "0")
	mustFlagValue(t, cmds[0], "--interface", "wgvpn0")
	mustFlagValue(t, cmds[0], "--operator-floor-check", "1")
	mustFlagValue(t, cmds[0], "--operator-min-operators", "2")
	mustFlagValue(t, cmds[0], "--issuer-quorum-check", "1")
	mustFlagValue(t, cmds[0], "--issuer-min-operators", "2")

	mustNotContainToken(t, cmds[1], "--subject")
	subjectFile := mustFlagNonEmptyValue(t, cmds[1], "--subject-file")
	if _, err := os.Stat(subjectFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("subject file should be cleaned up after connect; stat err=%v path=%q", err, subjectFile)
	}
	mustNotContainToken(t, cmds[1], "inv-test-2hop")
	mustFlagValue(t, cmds[1], "--path-profile", "2hop")
	mustFlagValue(t, cmds[1], "--session-reuse", "1")
	mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
	mustFlagValue(t, cmds[1], "--min-operators", "2")
	mustFlagValue(t, cmds[1], "--beta-profile", "1")
	mustFlagValue(t, cmds[1], "--prod-profile", "0")
	mustFlagValue(t, cmds[1], "--install-route", "0")
	mustFlagValue(t, cmds[1], "--ready-timeout-sec", "35")
}

func TestHandleConnectOneHopNormalizationAndOverrides(t *testing.T) {
	t.Run("one-hop defaults from profile alias", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
					"bootstrap_directory":"https://dir.example:8081",
					"invite_key":"inv-test-1hop",
					"path_profile":" speed-1hop "
				}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["profile"].(string); got != "1hop" {
			t.Fatalf("profile=%q want=1hop", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 3 {
			t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
		}
		mustFlagValue(t, cmds[0], "--operator-floor-check", "0")
		mustFlagValue(t, cmds[0], "--operator-min-operators", "1")
		mustFlagValue(t, cmds[0], "--issuer-quorum-check", "0")
		mustFlagValue(t, cmds[0], "--issuer-min-operators", "1")
		mustFlagValue(t, cmds[0], "--path-profile", "1hop")
		mustFlagValue(t, cmds[1], "--path-profile", "1hop")
		mustFlagValue(t, cmds[1], "--session-reuse", "1")
		mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
		mustFlagValue(t, cmds[1], "--min-operators", "1")
		mustFlagValue(t, cmds[1], "--beta-profile", "0")
		mustFlagValue(t, cmds[1], "--prod-profile", "0")
		mustFlagValue(t, cmds[1], "--install-route", "0")
	})

	t.Run("one-hop install_route override is ignored unless explicitly unlocked", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
				"bootstrap_directory":"https://dir.example:8081",
				"invite_key":"inv-test-1hop-up",
				"path_profile":"1hop",
				"run_preflight":false,
			"install_route":true
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--session-reuse", "1")
		mustFlagValue(t, cmds[0], "--allow-session-churn", "0")
		mustFlagValue(t, cmds[0], "--install-route", "0")
	})

	t.Run("one-hop install_route expert override and no preflight", func(t *testing.T) {
		t.Setenv("GPM_ALLOW_1HOP_INSTALL_ROUTE", "1")
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
				"bootstrap_directory":"https://dir.example:8081",
				"invite_key":"inv-test-1hop-up-expert",
				"path_profile":"1hop",
				"run_preflight":false,
				"install_route":true
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		mustFlagValue(t, cmds[0], "--install-route", "1")
	})
}

func TestHandleConnectThreeHopProdOverrides(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmSettlementChainBacked = true
	now := time.Now().UTC()
	wallet := "cosmos1connect3hopprod"
	reservationID := "res-connect-3hop-prod"
	reservationSessionID := "sess-connect-3hop-prod"
	svc.gpmSettlement = &gpmReserveFundsFinalityService{
		chainStatus:   settlement.OperationStatusConfirmed,
		chainFound:    true,
		reservationOK: true,
		reservation: settlement.FundReservation{
			ReservationID: reservationID,
			SessionID:     reservationSessionID,
			SubjectID:     wallet,
			AmountMicros:  200000,
			Status:        settlement.OperationStatusConfirmed,
		},
	}
	t.Setenv("LOCALAPI_TEST_STATUS_JSON", `{"connected":true,"running":true,"interface":"wgtest0","interface_state":"present","profile":"3hop","route_mode":"full-tunnel"}`)
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{"https://dir.example:8081"},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL
	svc.gpmState.putSession(gpmSession{
		Token:                     "gpm-connect-3hop-prod-token",
		WalletAddress:             wallet,
		WalletProvider:            "keplr",
		Role:                      "client",
		WalletBindingVerified:     true,
		EntitlementEvidenceSource: "chain",
		ClientTier:                2,
		StakeSatisfied:            true,
		PrepaidBalanceSatisfied:   true,
		CreatedAt:                 now,
		ExpiresAt:                 now.Add(time.Hour),
		BootstrapDirectory:        "https://dir.example:8081",
		InviteKey:                 "inv-test-3hop",
		PathProfile:               "3hop",
	})

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"session_token":"gpm-connect-3hop-prod-token",
		"reservation_id":"res-connect-3hop-prod",
		"reservation_session_id":"sess-connect-3hop-prod",
		"path_profile":"privacy",
		"interface":"wgtest0",
		"discovery_wait_sec":33,
		"ready_timeout_sec":66,
		"prod_profile":true
	}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["profile"].(string); got != "3hop" {
		t.Fatalf("profile=%q want=3hop", got)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 3 {
		t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
	}
	mustFlagValue(t, cmds[0], "--prod-profile", "1")
	mustFlagValue(t, cmds[0], "--interface", "wgtest0")
	mustFlagValue(t, cmds[0], "--discovery-wait-sec", "33")
	mustFlagValue(t, cmds[0], "--path-profile", "3hop")
	mustFlagValue(t, cmds[1], "--path-profile", "3hop")
	mustFlagValue(t, cmds[1], "--session-reuse", "1")
	mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
	mustFlagValue(t, cmds[1], "--prod-profile", "1")
	mustFlagValue(t, cmds[1], "--beta-profile", "1")
	mustFlagValue(t, cmds[1], "--ready-timeout-sec", "66")
	mustFlagValue(t, cmds[1], "--install-route", "1")

	code, payload = callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
	if code != http.StatusOK {
		t.Fatalf("disconnect status=%d body=%v", code, payload)
	}
	cmds = readCommandLog(t, logPath)
	if len(cmds) != 4 {
		t.Fatalf("commands=%d want=4 (%v)", len(cmds), cmds)
	}
	if cmds[3][0] != "client-vpn-down" {
		t.Fatalf("disconnect command=%q want client-vpn-down all=%v", cmds[3][0], cmds)
	}
	mustFlagValue(t, cmds[3], "--force-iface-cleanup", "0")
	if _, ok := commandFlags(cmds[3])["--iface"]; ok {
		t.Fatalf("public disconnect should not pass --iface for privileged cleanup, got=%v", cmds[3])
	}
}

func configureTestConnectManifest(t *testing.T, svc *Service, bootstrapDirectories ...string) {
	t.Helper()
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": bootstrapDirectories,
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL
}

func TestHandleConnectProdProfileRejectsOneHopOutsideProductionMode(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	configureTestConnectManifest(t, svc, "https://dir.example:8081")
	svc.gpmState.putSession(gpmSession{
		Token:                     "gpm-connect-prod-1hop-token",
		WalletAddress:             "cosmos1connectprod1hop",
		WalletProvider:            "keplr",
		Role:                      "client",
		WalletBindingVerified:     true,
		EntitlementEvidenceSource: "chain",
		ClientTier:                2,
		StakeSatisfied:            true,
		PrepaidBalanceSatisfied:   true,
		CreatedAt:                 now,
		ExpiresAt:                 now.Add(time.Hour),
		BootstrapDirectory:        "https://dir.example:8081",
		InviteKey:                 "wallet:cosmos1connectprod1hop",
		PathProfile:               "1hop",
	})

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"session_token":"gpm-connect-prod-1hop-token",
		"path_profile":"1hop",
		"prod_profile":true,
		"install_route":true,
		"run_preflight":false
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadRequest, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "strict 2hop or 3hop") {
		t.Fatalf("error=%q want strict profile guidance payload=%v", got, payload)
	}
	if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
		t.Fatalf("prod_profile 1hop should not execute commands, got=%v", cmds)
	}
}

func TestHandleConnectProdProfileRequiresSettlementReservationOutsideProductionMode(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmSettlementChainBacked = true
	now := time.Now().UTC()
	configureTestConnectManifest(t, svc, "https://dir.example:8081")
	svc.gpmState.putSession(gpmSession{
		Token:                     "gpm-connect-prod-profile-token",
		WalletAddress:             "cosmos1connectprodprofile",
		WalletProvider:            "keplr",
		Role:                      "client",
		WalletBindingVerified:     true,
		EntitlementEvidenceSource: "chain",
		ClientTier:                2,
		StakeSatisfied:            true,
		PrepaidBalanceSatisfied:   true,
		CreatedAt:                 now,
		ExpiresAt:                 now.Add(time.Hour),
		BootstrapDirectory:        "https://dir.example:8081",
		InviteKey:                 "wallet:cosmos1connectprodprofile",
		PathProfile:               "2hop",
	})

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"session_token":"gpm-connect-prod-profile-token",
		"path_profile":"2hop",
		"prod_profile":true,
		"run_preflight":false
	}`)
	if code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "reservation_id") {
		t.Fatalf("error=%q want reservation guidance payload=%v", got, payload)
	}
	if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
		t.Fatalf("prod_profile without reservation should not execute commands, got=%v", cmds)
	}
}

func TestHandleDisconnectProductionRequiresWalletBoundSession(t *testing.T) {
	t.Run("missing session token is rejected before command execution", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmConnectPolicyMode = "production"

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session_token is required") {
			t.Fatalf("error=%q want session_token guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing production session_token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("unbound wallet session is rejected before command execution", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmConnectPolicyMode = "production"
		token := seedGPMUnboundTestSession(t, svc, "gpm-disconnect-unbound", "cosmos1disconnectunbound")

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", `{"session_token":"`+token+`"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound session") {
			t.Fatalf("error=%q want wallet-bound guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("unbound production session should not execute commands, got=%v", cmds)
		}
	})
}

func TestHandleDisconnectProductionMatchesActiveReservationWallet(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	now := time.Now().UTC()
	const wallet = "cosmos1disconnectowner"
	if _, ok, reason := svc.gpmState.claimReservationForConnect("res-disconnect-active", "sess-disconnect-active", wallet, now); !ok {
		t.Fatalf("claim reservation: %s", reason)
	}
	if !svc.gpmState.markReservationConnectLaunched("res-disconnect-active", "sess-disconnect-active", wallet, now) {
		t.Fatal("mark reservation launched failed")
	}
	ownerToken := seedGPMTestSession(t, svc, "gpm-disconnect-owner", wallet, 3, true, true)
	otherToken := seedGPMTestSession(t, svc, "gpm-disconnect-other", "cosmos1disconnectother", 3, true, true)

	code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", `{"session_token":"`+otherToken+`"}`)
	if code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "does not match the active production reservation") {
		t.Fatalf("error=%q want active reservation guidance payload=%v", got, payload)
	}
	if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
		t.Fatalf("mismatched wallet should not execute disconnect command, got=%v", cmds)
	}

	code, payload = callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", `{"session_token":"`+ownerToken+`"}`)
	if code != http.StatusOK {
		t.Fatalf("owner disconnect status=%d payload=%v", code, payload)
	}
	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "client-vpn-down" {
		t.Fatalf("owner disconnect commands=%v want single client-vpn-down", cmds)
	}
}

func TestHandleConnectProductionModeForcesStrictProdProfile(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	svc.gpmConnectPolicySource = "test"
	svc.gpmSettlementChainBacked = true
	now := time.Now().UTC()
	wallet := "cosmos1connectprodforce"
	reservationID := "res-prod-force-1"
	reservationSessionID := "res-session-prod-force-1"
	svc.gpmSettlement = &gpmReserveFundsFinalityService{
		chainStatus:   settlement.OperationStatusConfirmed,
		chainFound:    true,
		reservationOK: true,
		reservation: settlement.FundReservation{
			ReservationID: reservationID,
			SessionID:     reservationSessionID,
			SubjectID:     wallet,
			AmountMicros:  200000,
			Status:        settlement.OperationStatusConfirmed,
		},
	}
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{"https://dir.example:8081"},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL
	svc.gpmState.putSession(gpmSession{
		Token:                     "gpm-connect-prod-force-token",
		WalletAddress:             wallet,
		WalletProvider:            "keplr",
		Role:                      "client",
		WalletBindingVerified:     true,
		EntitlementEvidenceSource: "chain",
		ClientTier:                2,
		StakeSatisfied:            true,
		PrepaidBalanceSatisfied:   true,
		CreatedAt:                 now,
		ExpiresAt:                 now.Add(time.Hour),
		BootstrapDirectory:        "https://dir.example:8081",
		InviteKey:                 "inv-test-prod-force",
		PathProfile:               "2hop",
	})

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"session_token":"gpm-connect-prod-force-token",
		"reservation_id":"res-prod-force-1",
		"reservation_session_id":"res-session-prod-force-1",
		"prod_profile":false
	}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 3 {
		t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
	}
	mustFlagValue(t, cmds[0], "--prod-profile", "1")
	mustFlagValue(t, cmds[1], "--prod-profile", "1")
	mustFlagValue(t, cmds[1], "--install-route", "1")
}

func TestGPMProductionConnectReservationClaimFailsClosedOnStateStoreLoadFailure(t *testing.T) {
	svc := &Service{
		gpmState:                 newGPMRuntimeState(),
		gpmStateStoreLoadFailed:  true,
		gpmStateStoreLoadFailure: "decode state store: invalid json",
	}
	code, payload := svc.claimGPMProductionConnectReservation(gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1stateloadfailed",
		ReservationID:        "res-state-load-failed",
		ReservationSessionID: "sess-state-load-failed",
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d payload=%v", code, http.StatusServiceUnavailable, payload)
	}
	if allowed, _ := payload["connect_allowed"].(bool); allowed {
		t.Fatalf("connect_allowed=%v want=false payload=%v", allowed, payload)
	}
	if got, _ := payload["state_store_error"].(string); !strings.Contains(got, "decode state store") {
		t.Fatalf("state_store_error=%q want decode state store payload=%v", got, payload)
	}
}

func TestGPMProductionConnectReservationClaimRequiresDurablePersist(t *testing.T) {
	blockerPath := filepath.Join(t.TempDir(), "gpm_state_blocker")
	if err := os.MkdirAll(blockerPath, 0o755); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	svc := &Service{
		gpmStateStorePath: blockerPath,
		gpmState:          newGPMRuntimeState(),
	}
	code, payload := svc.claimGPMProductionConnectReservation(gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1persistrequired",
		ReservationID:        "res-persist-required",
		ReservationSessionID: "sess-persist-required",
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d payload=%v", code, http.StatusServiceUnavailable, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "failed to persist production reservation claim") {
		t.Fatalf("error=%q payload=%v", got, payload)
	}
	_, _, _, _, _, claims := svc.gpmState.snapshotPersistent(time.Now().UTC())
	if len(claims) != 0 {
		t.Fatalf("claims=%v want none after failed durable claim", claims)
	}
}

func TestGPMProductionConnectLaunchStartedPersistsBeforeVPNLaunch(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	entitlement := gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1launchstarted",
		ReservationID:        "res-launch-started",
		ReservationSessionID: "sess-launch-started",
	}
	svc := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	if code, payload := svc.claimGPMProductionConnectReservation(entitlement); payload != nil {
		t.Fatalf("claim status=%d payload=%v", code, payload)
	}
	if code, payload := svc.markGPMProductionConnectReservationLaunchStarted(entitlement); payload != nil {
		t.Fatalf("launch-start status=%d payload=%v", code, payload)
	}

	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var store gpmStateStoreFile
	if err := json.Unmarshal(body, &store); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(store.ReservationClaims) != 1 {
		t.Fatalf("claims=%d want=1 body=%s", len(store.ReservationClaims), string(body))
	}
	claim := store.ReservationClaims[0]
	if claim.Status != "launching" {
		t.Fatalf("claim status=%q want=launching claim=%+v", claim.Status, claim)
	}
	if claim.LaunchStartedAt.IsZero() {
		t.Fatalf("launch_started_at not persisted claim=%+v", claim)
	}
}

func TestGPMProductionConnectLaunchedStatePersistsDurably(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	entitlement := gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1launchedpersisted",
		ReservationID:        "res-launched-persisted",
		ReservationSessionID: "sess-launched-persisted",
	}
	svc := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	if code, payload := svc.claimGPMProductionConnectReservation(entitlement); payload != nil {
		t.Fatalf("claim status=%d payload=%v", code, payload)
	}
	if code, payload := svc.markGPMProductionConnectReservationLaunchStarted(entitlement); payload != nil {
		t.Fatalf("launch-start status=%d payload=%v", code, payload)
	}
	if code, payload := svc.markGPMProductionConnectReservationLaunched(entitlement); payload != nil {
		t.Fatalf("launched status=%d payload=%v", code, payload)
	}

	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var store gpmStateStoreFile
	if err := json.Unmarshal(body, &store); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(store.ReservationClaims) != 1 {
		t.Fatalf("claims=%d want=1 body=%s", len(store.ReservationClaims), string(body))
	}
	claim := store.ReservationClaims[0]
	if claim.Status != "launched" {
		t.Fatalf("claim status=%q want=launched claim=%+v", claim.Status, claim)
	}
	if claim.LaunchedAt.IsZero() {
		t.Fatalf("launched_at not persisted claim=%+v", claim)
	}
}

func TestGPMProductionConnectLaunchedStateFailsClosedOnPersistFailure(t *testing.T) {
	blockerPath := filepath.Join(t.TempDir(), "gpm_state_blocker")
	if err := os.MkdirAll(blockerPath, 0o755); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	entitlement := gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1launchedblocked",
		ReservationID:        "res-launched-blocked",
		ReservationSessionID: "sess-launched-blocked",
	}
	svc := &Service{
		gpmStateStorePath: blockerPath,
		gpmState:          newGPMRuntimeState(),
	}
	claim, ok, reason := svc.gpmState.claimReservationForConnect(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, time.Now().UTC())
	if !ok {
		t.Fatalf("claim rejected claim=%+v reason=%q", claim, reason)
	}
	if !svc.gpmState.markReservationConnectLaunchStarted(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, time.Now().UTC()) {
		t.Fatal("expected launch-start marker")
	}

	code, payload := svc.markGPMProductionConnectReservationLaunched(entitlement)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d payload=%v", code, http.StatusServiceUnavailable, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "failed to persist production reservation launched state") {
		t.Fatalf("error=%q payload=%v", got, payload)
	}
	if status, _ := payload["reservation_claim_status"].(string); status != "launched" {
		t.Fatalf("reservation_claim_status=%q want launched payload=%v", status, payload)
	}
}

func TestGPMRuntimeStateRejectsRetryDuringFreshLaunchClaim(t *testing.T) {
	st := newGPMRuntimeState()
	now := time.Now().UTC()
	claim, ok, reason := st.claimReservationForConnect("res-fresh-launch", "sess-fresh-launch", "cosmos1fresh", now)
	if !ok {
		t.Fatalf("initial claim rejected claim=%+v reason=%q", claim, reason)
	}
	if !st.markReservationConnectLaunchStarted("res-fresh-launch", "sess-fresh-launch", "cosmos1fresh", now) {
		t.Fatal("expected launch-start marker")
	}

	_, ok, reason = st.claimReservationForConnect("res-fresh-launch", "sess-fresh-launch", "cosmos1fresh", now.Add(time.Minute))
	if ok || !strings.Contains(reason, "already started") {
		t.Fatalf("fresh launching claim ok=%v reason=%q want already started", ok, reason)
	}
}

func TestGPMProductionConnectRetainsStaleLaunchingClaimWhenRuntimeNotRunning(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	t.Setenv("LOCALAPI_TEST_STATUS_JSON", `{"connected":false,"profile":"2hop"}`)
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	svc.gpmStateStorePath = statePath
	svc.gpmState = newGPMRuntimeState()
	entitlement := gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1staledisconnected",
		ReservationID:        "res-stale-disconnected",
		ReservationSessionID: "sess-stale-disconnected",
	}
	staleAt := time.Now().UTC().Add(-(gpmReservationLaunchClaimTTL + time.Minute))
	if claim, ok, reason := svc.gpmState.claimReservationForConnect(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, staleAt); !ok {
		t.Fatalf("initial claim rejected claim=%+v reason=%q", claim, reason)
	}
	if !svc.gpmState.markReservationConnectLaunchStarted(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, staleAt) {
		t.Fatal("expected stale launch-start marker")
	}
	svc.persistGPMStateBestEffort("seed_stale_launching_claim")
	svc.gpmState = newGPMRuntimeState()
	svc.loadGPMStateBestEffort()

	if code, payload := svc.claimGPMProductionConnectReservation(entitlement); code != http.StatusConflict || payload == nil {
		t.Fatalf("claim after stale disconnected status=%d payload=%v want conflict", code, payload)
	} else if retained, _ := payload["reservation_claim_retained"].(bool); !retained {
		t.Fatalf("reservation_claim_retained=%v want=true payload=%v", retained, payload)
	}
	svc.gpmState.mu.RLock()
	claim := svc.gpmState.reservationClaims[entitlement.ReservationID]
	svc.gpmState.mu.RUnlock()
	if claim.Status != "launching" {
		t.Fatalf("claim status=%q want launching claim=%+v", claim.Status, claim)
	}
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var store gpmStateStoreFile
	if err := json.Unmarshal(body, &store); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(store.ReservationClaims) != 1 || store.ReservationClaims[0].Status != "launching" {
		t.Fatalf("persisted claims=%+v want one retained launching", store.ReservationClaims)
	}
	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "client-vpn-status" {
		t.Fatalf("commands=%v want one client-vpn-status reconciliation", cmds)
	}
}

func TestGPMProductionConnectMarksStaleLaunchingClaimLaunchedWhenRuntimeRunning(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	t.Setenv("LOCALAPI_TEST_STATUS_JSON", `{"connected":true,"reservation_id":"res-stale-running","session_id":"sess-stale-running"}`)
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	svc.gpmStateStorePath = statePath
	svc.gpmState = newGPMRuntimeState()
	entitlement := gpmProductionConnectEntitlement{
		WalletAddress:        "cosmos1stalerunning",
		ReservationID:        "res-stale-running",
		ReservationSessionID: "sess-stale-running",
	}
	staleAt := time.Now().UTC().Add(-(gpmReservationLaunchClaimTTL + time.Minute))
	if claim, ok, reason := svc.gpmState.claimReservationForConnect(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, staleAt); !ok {
		t.Fatalf("initial claim rejected claim=%+v reason=%q", claim, reason)
	}
	if !svc.gpmState.markReservationConnectLaunchStarted(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, staleAt) {
		t.Fatal("expected stale launch-start marker")
	}
	svc.persistGPMStateBestEffort("seed_stale_launching_claim")
	svc.gpmState = newGPMRuntimeState()
	svc.loadGPMStateBestEffort()

	code, payload := svc.claimGPMProductionConnectReservation(entitlement)
	if code != http.StatusConflict {
		t.Fatalf("status=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if status, _ := payload["reservation_claim_status"].(string); status != "launched" {
		t.Fatalf("reservation_claim_status=%q want launched payload=%v", status, payload)
	}
	svc.gpmState.mu.RLock()
	claim := svc.gpmState.reservationClaims[entitlement.ReservationID]
	svc.gpmState.mu.RUnlock()
	if claim.Status != "launched" || claim.LaunchedAt.IsZero() {
		t.Fatalf("claim=%+v want launched with timestamp", claim)
	}
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var store gpmStateStoreFile
	if err := json.Unmarshal(body, &store); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if len(store.ReservationClaims) != 1 || store.ReservationClaims[0].Status != "launched" {
		t.Fatalf("persisted claims=%+v want one launched", store.ReservationClaims)
	}
	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "client-vpn-status" {
		t.Fatalf("commands=%v want one client-vpn-status reconciliation", cmds)
	}
}

func TestHandleConnectFailuresAndValidation(t *testing.T) {
	t.Run("validation errors", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, _ := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{"bootstrap_directory":"https://dir.example:8081"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("missing invite key status=%d want=%d", code, http.StatusBadRequest)
		}

		code, _ = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{bad`)
		if code != http.StatusBadRequest {
			t.Fatalf("invalid json status=%d want=%d", code, http.StatusBadRequest)
		}
		code, _ = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{"bootstrap_directory":"https://dir.example:8081","invite_key":"inv"}{"extra":1}`)
		if code != http.StatusBadRequest {
			t.Fatalf("trailing json status=%d want=%d", code, http.StatusBadRequest)
		}

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"http://dir.example:8081",
			"invite_key":"inv-insecure-http"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("insecure bootstrap_directory status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "must use https for non-loopback hosts") {
			t.Fatalf("error=%q want insecure remote https guidance", got)
		}

		code, payload = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-with-control\u0000"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("invalid invite key status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid control characters") {
			t.Fatalf("error=%q want invite key control-char guidance", got)
		}

		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("validation failures should not execute commands, got=%v", cmds)
		}
	})

	t.Run("interface validation rejects non-wireguard names", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-invalid-iface",
			"interface":"eth0"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "interface must start with wg") {
			t.Fatalf("error=%q want interface validation message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid interface should not execute commands, got=%v", cmds)
		}
	})

	t.Run("preflight failure returns conflict and stops", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_PREFLIGHT_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-preflight-fail"
		}`)
		if code != http.StatusConflict {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["stage"].(string); got != "preflight" {
			t.Fatalf("stage=%q want=preflight", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 1 || cmds[0][0] != "client-vpn-preflight" {
			t.Fatalf("unexpected commands for preflight failure: %v", cmds)
		}
	})

	t.Run("connect failure after preflight returns bad gateway", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_UP_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-up-fail"
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["stage"].(string); got != "connect" {
			t.Fatalf("stage=%q want=connect", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-preflight" || cmds[1][0] != "client-vpn-up" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
	})
}

func TestHandleConnectSessionRequiredMode(t *testing.T) {
	configureSessionManifest := func(t *testing.T, svc *Service, now time.Time, bootstrapDirectories ...string) {
		t.Helper()
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": bootstrapDirectories,
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL
	}

	t.Run("manual overrides are rejected when legacy override policy is disabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = false

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-manual-disabled-by-policy"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "manual bootstrap_directory/invite_key overrides are disabled") || !strings.Contains(got, "registered session_token") {
			t.Fatalf("error=%q want manual-overrides-disabled + registered session_token guidance", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manual override rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("production mode rejects legacy manual overrides even if fields are relaxed", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectPolicyMode = "production"
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = false

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir-production-manual.example:8081",
			"invite_key":"inv-production-manual-disabled",
			"run_preflight":false
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "manual bootstrap_directory/invite_key overrides are disabled") {
			t.Fatalf("error=%q want production manual-overrides-disabled message", got)
		}

		code, payload = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "connect requires a registered session_token") {
			t.Fatalf("error=%q want production session-token-required message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("production guardrail rejections should not execute commands, got=%v", cmds)
		}
	})

	t.Run("production session token connect still requires trusted manifest revalidation", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectPolicyMode = "production"
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = false
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-production-connect-session-token",
			WalletAddress:         "cosmos1productionconnect",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    "https://dir-production-session.example:8081",
			InviteKey:             "wallet:cosmos1productionconnect",
		})
		svc.gpmMainDomain = "https://127.0.0.1:1"
		svc.gpmManifestURL = "https://127.0.0.1:1/v1/bootstrap/manifest"

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-production-connect-session-token",
			"run_preflight":false
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "trusted manifest") {
			t.Fatalf("error=%q want trusted-manifest revalidation failure", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("trusted-manifest rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("manual overrides remain allowed when trusted-manifest binding policy is disabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = false

		now := time.Now().UTC()
		configureSessionManifest(t, svc, now, "https://dir-trusted-only.example:8081")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir-manual-policy-disabled.example:8081",
			"invite_key":"inv-manual-enabled-by-policy",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir-manual-policy-disabled.example:8081")
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
	})

	t.Run("manual overrides are allowed when trusted-manifest binding policy is enabled and bootstrap is trusted", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = true

		now := time.Now().UTC()
		trustedBootstrap := "https://dir-manual-trusted.example:8081"
		configureSessionManifest(t, svc, now, trustedBootstrap, "https://dir-manual-secondary.example:8081")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir-manual-trusted.example:8081",
			"invite_key":"inv-manual-trusted-bootstrap",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", trustedBootstrap)
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
	})

	t.Run("manual trusted-manifest comparison uses canonical bootstrap directory url", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = true

		now := time.Now().UTC()
		configureSessionManifest(t, svc, now, "https://Dir-Manual-Canonical.example:443/")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir-manual-canonical.example/",
			"invite_key":"inv-manual-canonical-bootstrap",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir-manual-canonical.example")
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
	})

	t.Run("manual overrides fail closed when trusted-manifest binding policy is enabled and bootstrap is not trusted", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = true

		now := time.Now().UTC()
		configureSessionManifest(t, svc, now, "https://dir-manual-trusted-only.example:8081")
		untrustedBootstrap := "https://dir-manual-untrusted.example:8081"

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", fmt.Sprintf(`{
			"bootstrap_directory":%q,
			"invite_key":"inv-manual-untrusted-bootstrap",
			"run_preflight":false
		}`, untrustedBootstrap))
		if code != http.StatusBadRequest && code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(strings.ToLower(errMsg), "trusted manifest") && !strings.Contains(strings.ToLower(errMsg), "trusted bootstrap") {
			t.Fatalf("error=%q want trusted-manifest rejection guidance", errMsg)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("trusted-manifest rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("manual overrides fail closed when trusted-manifest binding policy is enabled and manifest resolution fails", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = true

		svc.gpmMainDomain = "https://127.0.0.1:1"
		svc.gpmManifestURL = "https://127.0.0.1:1/v1/bootstrap/manifest"

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir-manual-manifest-failure.example:8081",
			"invite_key":"inv-manual-manifest-failure",
			"run_preflight":false
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(strings.ToLower(errMsg), "manifest") {
			t.Fatalf("error=%q want manifest-resolution failure guidance", errMsg)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manifest-resolution rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("manual overrides fail closed when an explicitly provided session token is invalid", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmState = newGPMRuntimeState()

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-missing-token",
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-manual-invalid-session",
			"run_preflight":false
		}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "invalid or expired session_token" {
			t.Fatalf("error=%q want invalid-or-expired-session-token", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid session rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("manual overrides are rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-manual-disabled"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "manual bootstrap_directory/invite_key overrides are disabled") {
			t.Fatalf("error=%q want manual-overrides-disabled message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manual override rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session token is required when mode is enabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "connect requires a registered session_token") {
			t.Fatalf("error=%q want session-required message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("session-required rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("invalid session token fails closed with unauthorized in session-required mode", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-missing-token"
		}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "invalid or expired session_token" {
			t.Fatalf("error=%q want invalid-or-expired-session-token", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid session rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session token must be registered for connect in session-required mode", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-unregistered-session-token",
			WalletAddress:         "cosmos1connectunregistered",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-unregistered-session-token"
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "not registered for connect") {
			t.Fatalf("error=%q want not-registered-for-connect guidance", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("unregistered session rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("registered session token resolves connect secrets", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		configureSessionManifest(t, svc, now, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-token",
			WalletAddress:         "cosmos1connectsession",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    "https://dir.example:8081",
			InviteKey:             "wallet:cosmos1connectsession",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-token",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir.example:8081")
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
	})

	t.Run("registered unbound session token is rejected before connect", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		configureSessionManifest(t, svc, now, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:              "gpm-connect-unbound-session-token",
			WalletAddress:      "cosmos1connectunbound",
			WalletProvider:     "keplr",
			Role:               "client",
			CreatedAt:          now,
			ExpiresAt:          now.Add(time.Hour),
			BootstrapDirectory: "https://dir.example:8081",
			InviteKey:          "wallet:cosmos1connectunbound",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-unbound-session-token",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound session is required for connect") {
			t.Fatalf("error=%q want wallet-bound rejection", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("unbound session rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("selected session bootstrap directory works and uses selected value", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		primaryBootstrap := "https://dir-primary.example:8081"
		selectedBootstrap := "https://dir-selected.example:8081"
		configureSessionManifest(t, svc, now, primaryBootstrap, selectedBootstrap)
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-selected-token",
			WalletAddress:         "cosmos1connectselected",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    primaryBootstrap,
			BootstrapDirectories:  []string{primaryBootstrap, selectedBootstrap},
			InviteKey:             "wallet:cosmos1connectselected",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-selected-token",
			"session_bootstrap_directory":"https://dir-selected.example:8081",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["bootstrap_directory"].(string); got != selectedBootstrap {
			t.Fatalf("bootstrap_directory=%q want=%q payload=%v", got, selectedBootstrap, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", selectedBootstrap)
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
	})

	t.Run("selected session bootstrap directory without session_token fails", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_bootstrap_directory":"https://dir-selected.example:8081"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "session_bootstrap_directory requires session_token" {
			t.Fatalf("error=%q want session_bootstrap_directory requires session_token", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing-session rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("selected session bootstrap directory conflicts with manual overrides", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		configureSessionManifest(t, svc, now, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-conflict-token",
			WalletAddress:         "cosmos1connectconflict",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    "https://dir.example:8081",
			InviteKey:             "wallet:cosmos1connectconflict",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-conflict-token",
			"session_bootstrap_directory":"https://dir.example:8081",
			"bootstrap_directory":"https://manual.example:8081",
			"invite_key":"inv-manual-conflict"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session_bootstrap_directory cannot be combined") {
			t.Fatalf("error=%q want session_bootstrap_directory conflict guidance", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("conflict rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("manual invite override with session token fails closed when trusted-manifest binding policy is enabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmLegacyConnectRequireTrustedManifestBootstrap = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		bootstrapDirectory := "https://dir-session.example:8081"
		configureSessionManifest(t, svc, now, bootstrapDirectory)
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-manual-invite-override-token",
			WalletAddress:         "cosmos1manualinviteoverride",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    bootstrapDirectory,
			InviteKey:             "wallet:cosmos1manualinviteoverride",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-manual-invite-override-token",
			"invite_key":"inv-manual-override-should-fail",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "manual invite_key override cannot be combined with session_token") {
			t.Fatalf("error=%q want manual-invite/session-token rejection guidance", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manual invite override rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("selected session bootstrap directory must be trusted by the session", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		trustedBootstrap := "https://dir-trusted.example:8081"
		untrustedBootstrap := "https://dir-untrusted.example:8081"
		configureSessionManifest(t, svc, now, trustedBootstrap)
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-untrusted-token",
			WalletAddress:         "cosmos1connectuntrusted",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    trustedBootstrap,
			BootstrapDirectories:  []string{trustedBootstrap},
			InviteKey:             "wallet:cosmos1connectuntrusted",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", fmt.Sprintf(`{
			"session_token":"gpm-connect-session-untrusted-token",
			"session_bootstrap_directory":%q
		}`, untrustedBootstrap))
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "not in the session's trusted bootstrap directories") {
			t.Fatalf("error=%q want trusted-bootstrap rejection", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("untrusted selection rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session bootstrap directories fail over from first to second", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		firstBootstrap := "https://dir-first.example:8081"
		secondBootstrap := "https://dir-second.example:8081"
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": []string{firstBootstrap, secondBootstrap},
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-failover-token",
			WalletAddress:         "cosmos1connectfailover",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    firstBootstrap,
			BootstrapDirectories:  []string{firstBootstrap, secondBootstrap},
			InviteKey:             "wallet:cosmos1connectfailover",
		})
		t.Setenv("LOCALAPI_TEST_UP_FAIL_BOOTSTRAP", firstBootstrap)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-failover-token"
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["bootstrap_directory"].(string); got != secondBootstrap {
			t.Fatalf("bootstrap_directory=%q want=%q payload=%v", got, secondBootstrap, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 5 {
			t.Fatalf("commands=%d want=5 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-preflight" || cmds[1][0] != "client-vpn-up" || cmds[2][0] != "client-vpn-preflight" || cmds[3][0] != "client-vpn-up" || cmds[4][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", firstBootstrap)
		mustFlagValue(t, cmds[1], "--bootstrap-directory", firstBootstrap)
		mustFlagValue(t, cmds[2], "--bootstrap-directory", secondBootstrap)
		mustFlagValue(t, cmds[3], "--bootstrap-directory", secondBootstrap)
	})

	t.Run("session token fails closed when manifest drift revokes all registered bootstrap directories", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		manifestBootstrap := "https://dir-trusted-current.example:8081"
		manifestHits := 0
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			manifestHits++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": []string{manifestBootstrap},
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL

		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-drift-token",
			WalletAddress:         "cosmos1connectdrift",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    "https://dir-revoked-primary.example:8081",
			BootstrapDirectories:  []string{"https://dir-revoked-primary.example:8081", "https://dir-revoked-secondary.example:8081"},
			InviteKey:             "wallet:cosmos1connectdrift",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-drift-token"
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "no registered bootstrap_directory remains trusted") {
			t.Fatalf("error=%q want trusted-manifest drift guidance", got)
		}
		if manifestHits == 0 {
			t.Fatalf("expected manifest revalidation to be attempted")
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manifest drift rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session token connect succeeds when at least one registered bootstrap directory remains trusted", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		now := time.Now().UTC()
		revokedBootstrap := "https://dir-revoked-primary.example:8081"
		trustedBootstrap := "https://dir-trusted-secondary.example:8081"
		manifestHits := 0
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			manifestHits++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": []string{trustedBootstrap, "https://dir-new-third.example:8081"},
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL

		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-session-partial-trust-token",
			WalletAddress:         "cosmos1connectpartialtrust",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             now,
			ExpiresAt:             now.Add(time.Hour),
			BootstrapDirectory:    revokedBootstrap,
			BootstrapDirectories:  []string{revokedBootstrap, trustedBootstrap},
			InviteKey:             "wallet:cosmos1connectpartialtrust",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-partial-trust-token",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["bootstrap_directory"].(string); got != trustedBootstrap {
			t.Fatalf("bootstrap_directory=%q want=%q payload=%v", got, trustedBootstrap, payload)
		}
		if manifestHits == 0 {
			t.Fatalf("expected manifest revalidation to be attempted")
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--bootstrap-directory", trustedBootstrap)
	})
}

func TestHandleConnectSessionPathProfilePolicyEnforcement(t *testing.T) {
	resetConnectDefaultEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
		t.Setenv("CLIENT_PATH_PROFILE", "")
		t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
		t.Setenv("CLIENT_WG_INTERFACE", "")
		t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")
		t.Setenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT", "")
	}
	configureConnectManifest := func(t *testing.T, svc *Service, bootstrapDirectories ...string) {
		t.Helper()
		now := time.Now().UTC()
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": bootstrapDirectories,
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL
	}

	t.Run("session-required mode rejects conflicting request path_profile", func(t *testing.T) {
		resetConnectDefaultEnv(t)
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		configureConnectManifest(t, svc, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-profile-conflict-token",
			WalletAddress:         "cosmos1profileconflict",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			BootstrapDirectory:    "https://dir.example:8081",
			InviteKey:             "wallet:cosmos1profileconflict",
			PathProfile:           "3hop",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-profile-conflict-token",
			"path_profile":"1hop",
			"run_preflight":false
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(strings.ToLower(got), "path_profile") {
			t.Fatalf("error=%q want path_profile conflict guidance", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("conflicting session/request path_profile should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session-present mode inherits missing request path_profile and applies session policy", func(t *testing.T) {
		resetConnectDefaultEnv(t)
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		configureConnectManifest(t, svc, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-connect-profile-inherit-token",
			WalletAddress:         "cosmos1profileinherit",
			WalletProvider:        "keplr",
			Role:                  "client",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			BootstrapDirectory:    "https://dir.example:8081",
			InviteKey:             "wallet:cosmos1profileinherit",
			PathProfile:           "1hop",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-profile-inherit-token",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["profile"].(string); got != "1hop" {
			t.Fatalf("profile=%q want=1hop", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--path-profile", "1hop")
		mustFlagValue(t, cmds[0], "--min-operators", "1")
		mustFlagValue(t, cmds[0], "--operator-floor-check", "0")
		mustFlagValue(t, cmds[0], "--operator-min-operators", "1")
		mustFlagValue(t, cmds[0], "--issuer-quorum-check", "0")
		mustFlagValue(t, cmds[0], "--issuer-min-operators", "1")
		mustFlagValue(t, cmds[0], "--beta-profile", "0")
		mustFlagValue(t, cmds[0], "--prod-profile", "0")
		mustFlagValue(t, cmds[0], "--install-route", "0")
	})

	t.Run("empty session path_profile keeps request path_profile compatibility", func(t *testing.T) {
		resetConnectDefaultEnv(t)
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		configureConnectManifest(t, svc, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                   "gpm-connect-profile-compat-token",
			WalletAddress:           "cosmos1profilecompat",
			WalletProvider:          "keplr",
			Role:                    "client",
			WalletBindingVerified:   true,
			ClientTier:              2,
			StakeSatisfied:          true,
			PrepaidBalanceSatisfied: true,
			CreatedAt:               time.Now().UTC(),
			ExpiresAt:               time.Now().UTC().Add(time.Hour),
			BootstrapDirectory:      "https://dir.example:8081",
			InviteKey:               "wallet:cosmos1profilecompat",
			PathProfile:             "",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-profile-compat-token",
			"path_profile":"3hop",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["profile"].(string); got != "3hop" {
			t.Fatalf("profile=%q want=3hop", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--path-profile", "3hop")
		mustFlagValue(t, cmds[0], "--min-operators", "2")
		mustFlagValue(t, cmds[0], "--beta-profile", "1")
	})

	t.Run("session 3hop requires micro-relay entitlement", func(t *testing.T) {
		resetConnectDefaultEnv(t)
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		configureConnectManifest(t, svc, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                   "gpm-connect-tier1-3hop-token",
			WalletAddress:           "cosmos1tier1connect3hop",
			WalletProvider:          "keplr",
			Role:                    "client",
			WalletBindingVerified:   true,
			ClientTier:              1,
			StakeSatisfied:          true,
			PrepaidBalanceSatisfied: true,
			CreatedAt:               time.Now().UTC(),
			ExpiresAt:               time.Now().UTC().Add(time.Hour),
			BootstrapDirectory:      "https://dir.example:8081",
			InviteKey:               "wallet:cosmos1tier1connect3hop",
			PathProfile:             "3hop",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-tier1-3hop-token",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "Tier 2 or Tier 3") {
			t.Fatalf("error=%q want Tier 2/3 guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("tier-locked 3hop connect should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session stake and prepaid entitlements are fixed at issuance", func(t *testing.T) {
		resetConnectDefaultEnv(t)
		t.Setenv("GPM_STAKE_SATISFIED", "1")
		t.Setenv("GPM_PREPAID_BALANCE_SATISFIED", "1")
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		configureConnectManifest(t, svc, "https://dir.example:8081")
		svc.gpmState.putSession(gpmSession{
			Token:                   "gpm-connect-session-bound-entitlements",
			WalletAddress:           "cosmos1sessionboundentitlements",
			WalletProvider:          "keplr",
			Role:                    "client",
			WalletBindingVerified:   true,
			ClientTier:              2,
			StakeSatisfied:          false,
			PrepaidBalanceSatisfied: false,
			CreatedAt:               time.Now().UTC(),
			ExpiresAt:               time.Now().UTC().Add(time.Hour),
			BootstrapDirectory:      "https://dir.example:8081",
			InviteKey:               "wallet:cosmos1sessionboundentitlements",
			PathProfile:             "3hop",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-bound-entitlements",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "stake requirement is not satisfied") {
			t.Fatalf("error=%q want session-bound stake guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("env-upgraded 3hop connect should not execute commands, got=%v", cmds)
		}
	})

	t.Run("manual 3hop requires authenticated contribution entitlement", func(t *testing.T) {
		resetConnectDefaultEnv(t)
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"http://127.0.0.1:8081",
			"invite_key":"inv-manual-3hop",
			"path_profile":"3hop",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "authenticated Tier 2 or Tier 3") {
			t.Fatalf("error=%q want authenticated Tier 2/3 guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manual 3hop without session should not execute commands, got=%v", cmds)
		}
	})
}

func TestHandleConnectProductionEntitlementGate(t *testing.T) {
	configureConnectManifest := func(t *testing.T, svc *Service, bootstrapDirectories ...string) {
		t.Helper()
		now := time.Now().UTC()
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": bootstrapDirectories,
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL
	}
	seedConnectSession := func(t *testing.T, svc *Service, token string, stakeSatisfied bool, prepaidSatisfied bool) string {
		t.Helper()
		if svc.gpmState == nil {
			svc.gpmState = newGPMRuntimeState()
		}
		svc.gpmState.putSession(gpmSession{
			Token:                     token,
			WalletAddress:             "cosmos1connectprod",
			WalletProvider:            "keplr",
			Role:                      "client",
			WalletBindingVerified:     true,
			EntitlementEvidenceSource: "chain",
			ClientTier:                2,
			StakeSatisfied:            stakeSatisfied,
			PrepaidBalanceSatisfied:   prepaidSatisfied,
			CreatedAt:                 time.Now().UTC(),
			ExpiresAt:                 time.Now().UTC().Add(time.Hour),
			BootstrapDirectory:        "https://dir.example:8081",
			InviteKey:                 "wallet:cosmos1connectprod",
			PathProfile:               "2hop",
		})
		return token
	}
	newProductionConnectService := func(t *testing.T, status settlement.OperationStatus, found bool) (*Service, string, string) {
		t.Helper()
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmConnectPolicyMode = "production"
		svc.gpmConnectRequireSession = true
		svc.gpmSettlementChainBacked = true
		svc.gpmSettlementBackend = "cosmos"
		svc.gpmSettlement = &gpmReserveFundsFinalityService{
			returnedStatus: settlement.OperationStatusSubmitted,
			chainStatus:    status,
			chainFound:     found,
			reservation: settlement.FundReservation{
				SessionID:    "vpn-session-prod",
				SubjectID:    "cosmos1connectprod",
				AmountMicros: 200000,
				Currency:     "TDPNC",
				Status:       status,
			},
			reservationOK: found,
		}
		configureConnectManifest(t, svc, "https://dir.example:8081")
		token := seedConnectSession(t, svc, "gpm-connect-prod-token", true, true)
		return svc, logPath, token
	}

	t.Run("missing reservation fails closed before launching vpn", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "confirmed settlement reservation_id") {
			t.Fatalf("error=%q want confirmed reservation guidance payload=%v", got, payload)
		}
		if allowed, _ := payload["connect_allowed"].(bool); allowed {
			t.Fatalf("connect_allowed=%v want=false payload=%v", allowed, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing reservation should not execute commands, got=%v", cmds)
		}
	})

	t.Run("local only account eligibility fails closed before launching vpn", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)
		markGPMTestSessionEntitlementsLocal(t, svc, token)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "trusted chain or signed entitlement evidence") {
			t.Fatalf("error=%q want entitlement evidence guidance payload=%v", got, payload)
		}
		if trusted, _ := payload["entitlement_evidence_trusted"].(bool); trusted {
			t.Fatalf("entitlement_evidence_trusted=%v want=false payload=%v", trusted, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("local-only eligibility should not execute commands, got=%v", cmds)
		}
	})

	t.Run("missing stake fails closed for normal 2hop connect", func(t *testing.T) {
		svc, logPath, _ := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)
		token := seedConnectSession(t, svc, "gpm-connect-prod-no-stake", false, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "stake is required") {
			t.Fatalf("error=%q want stake guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing stake should not execute commands, got=%v", cmds)
		}
	})

	t.Run("pending reservation fails closed before launching vpn", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusSubmitted, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-pending",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusAccepted {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusAccepted, payload)
		}
		if allowed, _ := payload["connect_allowed"].(bool); allowed {
			t.Fatalf("connect_allowed=%v want=false payload=%v", allowed, payload)
		}
		if state, _ := payload["reservation_finalization_state"].(string); state != "pending_chain_confirmation" {
			t.Fatalf("reservation_finalization_state=%q want pending_chain_confirmation payload=%v", state, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("pending reservation should not execute commands, got=%v", cmds)
		}
	})

	t.Run("missing reservation session id fails closed", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"run_preflight":false
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadRequest, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "reservation_session_id is required") {
			t.Fatalf("error=%q want reservation_session_id guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing reservation_session_id should not execute commands, got=%v", cmds)
		}
	})

	t.Run("cross wallet reservation fails closed", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)
		svc.gpmSettlement.(*gpmReserveFundsFinalityService).reservation.SubjectID = "cosmos1otherwallet"

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "signed-in wallet") {
			t.Fatalf("error=%q want wallet binding guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("cross-wallet reservation should not execute commands, got=%v", cmds)
		}
	})

	t.Run("wrong reservation session id fails closed", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-other",
			"run_preflight":false
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session_id does not match") {
			t.Fatalf("error=%q want session binding guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("wrong-session reservation should not execute commands, got=%v", cmds)
		}
	})

	t.Run("wrong reservation amount fails closed", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)
		svc.gpmSettlement.(*gpmReserveFundsFinalityService).reservation.AmountMicros = 300000

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusConflict {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusConflict, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "public VPN reservation amount") {
			t.Fatalf("error=%q want fixed amount guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("wrong-amount reservation should not execute commands, got=%v", cmds)
		}
	})

	t.Run("explicit production no-route fails closed before launching vpn", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"install_route":false,
			"run_preflight":false
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadRequest, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "production connect requires install_route=true") {
			t.Fatalf("error=%q want production install_route guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("explicit no-route production connect should not execute commands, got=%v", cmds)
		}
	})

	t.Run("confirmed reservation launches vpn and reports entitlement", func(t *testing.T) {
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		connectBody := `{
			"session_token":"` + token + `",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`
		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", connectBody)
		if code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusOK, payload)
		}
		if allowed, _ := payload["connect_allowed"].(bool); !allowed {
			t.Fatalf("connect_allowed=%v want=true payload=%v", allowed, payload)
		}
		if status, _ := payload["reservation_chain_status"].(string); status != string(settlement.OperationStatusConfirmed) {
			t.Fatalf("reservation_chain_status=%q want confirmed payload=%v", status, payload)
		}
		if sessionID, _ := payload["reservation_session_id"].(string); sessionID != "vpn-session-prod" {
			t.Fatalf("reservation_session_id=%q want vpn-session-prod payload=%v", sessionID, payload)
		}
		if source, _ := payload["reservation_status_source"].(string); source != "chain_status_query" {
			t.Fatalf("reservation_status_source=%q want chain_status_query payload=%v", source, payload)
		}
		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--install-route", "1")

		code, payload = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", connectBody)
		if code != http.StatusConflict {
			t.Fatalf("reuse status=%d want=%d body=%v", code, http.StatusConflict, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "already been used") {
			t.Fatalf("reuse error=%q want already-used guidance payload=%v", got, payload)
		}
		if cmds = readCommandLog(t, logPath); len(cmds) != 2 {
			t.Fatalf("reservation reuse should not execute more commands, got=%v", cmds)
		}
	})

	t.Run("production connect stages wallet reservation subject instead of custom invite key", func(t *testing.T) {
		t.Setenv("LOCALAPI_TEST_EXPECT_SUBJECT_VALUE", "cosmos1connectprod")
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)
		session, ok, err := svc.gpmSessionFromToken(token)
		if err != nil {
			t.Fatalf("seeded session violates wallet policy: %v", err)
		}
		if !ok {
			t.Fatalf("missing seeded session")
		}
		session.InviteKey = "custom-invite-key-that-is-not-the-wallet-subject"
		svc.gpmState.putSession(session)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusOK, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		claim := svc.gpmState.reservationClaims["res-prod-confirmed"]
		if claim.Status != "launched" {
			t.Fatalf("reservation claim status=%q want launched claim=%+v", claim.Status, claim)
		}
	})

	t.Run("post launch readiness failures release only when stopped is proven", func(t *testing.T) {
		cases := []struct {
			name         string
			statusJSON   string
			wantReason   string
			wantReleased bool
		}{
			{
				name:         "running false",
				statusJSON:   `{"running":false,"interface":"wgvpn0","interface_state":"present","route_mode":"full-tunnel"}`,
				wantReason:   "running=false",
				wantReleased: true,
			},
			{
				name:       "interface missing",
				statusJSON: `{"running":true,"interface":"wgother0","interface_state":"present","route_mode":"full-tunnel"}`,
				wantReason: "expected WireGuard interface",
			},
			{
				name:       "no route",
				statusJSON: `{"running":true,"interface":"wgvpn0","interface_state":"present","route_mode":"no-route"}`,
				wantReason: "unsafe route_mode",
			},
			{
				name:       "split route",
				statusJSON: `{"running":true,"interface":"wgvpn0","interface_state":"present","route_mode":"split-route"}`,
				wantReason: "unsafe route_mode",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Setenv("LOCALAPI_TEST_STATUS_JSON", tc.statusJSON)
				svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

				code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
					"session_token":"`+token+`",
					"reservation_id":"res-prod-confirmed",
					"reservation_session_id":"vpn-session-prod",
					"run_preflight":false
				}`)
				if code != http.StatusBadGateway {
					t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadGateway, payload)
				}
				if got, _ := payload["error"].(string); got != "production VPN readiness check failed after launch" {
					t.Fatalf("error=%q payload=%v", got, payload)
				}
				if got, _ := payload["readiness_error"].(string); !strings.Contains(got, tc.wantReason) {
					t.Fatalf("readiness_error=%q want contains %q payload=%v", got, tc.wantReason, payload)
				}
				if allowed, _ := payload["connect_allowed"].(bool); allowed {
					t.Fatalf("connect_allowed=%v want=false payload=%v", allowed, payload)
				}
				if released, _ := payload["reservation_claim_released"].(bool); released != tc.wantReleased {
					t.Fatalf("reservation_claim_released=%v want %v payload=%v", released, tc.wantReleased, payload)
				}
				if retained, _ := payload["reservation_claim_retained"].(bool); retained != !tc.wantReleased {
					t.Fatalf("reservation_claim_retained=%v want %v payload=%v", retained, !tc.wantReleased, payload)
				}
				wantClaimStatus := "launching"
				if tc.wantReleased {
					wantClaimStatus = "released"
				}
				if status, _ := payload["reservation_claim_status"].(string); status != wantClaimStatus {
					t.Fatalf("reservation_claim_status=%q want %q payload=%v", status, wantClaimStatus, payload)
				}
				if attempted, _ := payload["teardown_attempted"].(bool); !attempted {
					t.Fatalf("teardown_attempted=%v want true payload=%v", attempted, payload)
				}

				cmds := readCommandLog(t, logPath)
				if len(cmds) != 3 {
					t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
				}
				if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" || cmds[2][0] != "client-vpn-down" {
					t.Fatalf("unexpected command order after readiness failure: %v", cmds)
				}
				mustFlagValue(t, cmds[0], "--install-route", "1")
				mustFlagValue(t, cmds[2], "--iface", "wgvpn0")

				svc.gpmState.mu.RLock()
				claim, claimed := svc.gpmState.reservationClaims["res-prod-confirmed"]
				svc.gpmState.mu.RUnlock()
				if tc.wantReleased && claimed {
					t.Fatalf("reservation claim should be released after readiness failure")
				}
				if !tc.wantReleased {
					if !claimed {
						t.Fatalf("ambiguous readiness failure should retain reservation claim")
					}
					if claim.Status != "launching" {
						t.Fatalf("claim status=%q want launching claim=%+v", claim.Status, claim)
					}
				}
			})
		}
	})

	t.Run("post launch readiness status failure retains reservation", func(t *testing.T) {
		t.Setenv("LOCALAPI_TEST_STATUS_FAIL", "1")
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadGateway, payload)
		}
		if released, _ := payload["reservation_claim_released"].(bool); released {
			t.Fatalf("reservation_claim_released=%v want=false payload=%v", released, payload)
		}
		if retained, _ := payload["reservation_claim_retained"].(bool); !retained {
			t.Fatalf("reservation_claim_retained=%v want=true payload=%v", retained, payload)
		}
		if _, ok := payload["status_error"].(string); !ok {
			t.Fatalf("status_error missing payload=%v", payload)
		}
		cmds := readCommandLog(t, logPath)
		if len(cmds) != 3 || cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" || cmds[2][0] != "client-vpn-down" {
			t.Fatalf("unexpected command order after status failure: %v", cmds)
		}
		svc.gpmState.mu.RLock()
		claim, claimed := svc.gpmState.reservationClaims["res-prod-confirmed"]
		svc.gpmState.mu.RUnlock()
		if !claimed || claim.Status != "launching" {
			t.Fatalf("status failure should retain launching claim claimed=%v claim=%+v", claimed, claim)
		}
	})

	t.Run("post launch teardown failure retains reservation", func(t *testing.T) {
		t.Setenv("LOCALAPI_TEST_STATUS_JSON", `{"running":false,"interface":"wgvpn0","interface_state":"absent","route_mode":"full-tunnel"}`)
		t.Setenv("LOCALAPI_TEST_DOWN_FAIL", "1")
		svc, _, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadGateway, payload)
		}
		if released, _ := payload["reservation_claim_released"].(bool); released {
			t.Fatalf("reservation_claim_released=%v want=false payload=%v", released, payload)
		}
		if retained, _ := payload["reservation_claim_retained"].(bool); !retained {
			t.Fatalf("reservation_claim_retained=%v want=true payload=%v", retained, payload)
		}
		if _, ok := payload["teardown_error"].(string); !ok {
			t.Fatalf("teardown_error missing payload=%v", payload)
		}
		svc.gpmState.mu.RLock()
		claim, claimed := svc.gpmState.reservationClaims["res-prod-confirmed"]
		svc.gpmState.mu.RUnlock()
		if !claimed || claim.Status != "launching" {
			t.Fatalf("teardown failure should retain launching claim claimed=%v claim=%+v", claimed, claim)
		}
	})

	t.Run("post launch state persist failure tears down and fails closed", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "gpm_state.json")
		t.Setenv("LOCALAPI_TEST_BLOCK_STATE_PATH_AFTER_UP", statePath)
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)
		svc.gpmStateStorePath = statePath

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusServiceUnavailable, payload)
		}
		if stage, _ := payload["stage"].(string); stage != "connect_state_persist" {
			t.Fatalf("stage=%q want connect_state_persist payload=%v", stage, payload)
		}
		if attempted, _ := payload["teardown_attempted"].(bool); !attempted {
			t.Fatalf("teardown_attempted=%v want true payload=%v", attempted, payload)
		}
		cmds := readCommandLog(t, logPath)
		if len(cmds) != 3 {
			t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" || cmds[2][0] != "client-vpn-down" {
			t.Fatalf("unexpected command order after persist failure: %v", cmds)
		}
		mustFlagValue(t, cmds[2], "--iface", "wgvpn0")

		svc.gpmState.mu.RLock()
		claim := svc.gpmState.reservationClaims["res-prod-confirmed"]
		svc.gpmState.mu.RUnlock()
		if claim.Status != "launched" {
			t.Fatalf("claim status=%q want launched after ambiguous post-launch persist failure", claim.Status)
		}
	})

	t.Run("failed connect retains launching reservation claim for reconciliation", func(t *testing.T) {
		t.Setenv("LOCALAPI_TEST_UP_FAIL", "1")
		svc, logPath, token := newProductionConnectService(t, settlement.OperationStatusConfirmed, true)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"`+token+`",
			"reservation_id":"res-prod-confirmed",
			"reservation_session_id":"vpn-session-prod",
			"run_preflight":false
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusBadGateway, payload)
		}
		if retained, _ := payload["reservation_claim_retained"].(bool); !retained {
			t.Fatalf("reservation_claim_retained=%v want true payload=%v", retained, payload)
		}
		if status, _ := payload["reservation_claim_status"].(string); status != "launching" {
			t.Fatalf("reservation_claim_status=%q want launching payload=%v", status, payload)
		}
		svc.gpmState.mu.RLock()
		claim, claimed := svc.gpmState.reservationClaims["res-prod-confirmed"]
		svc.gpmState.mu.RUnlock()
		if !claimed {
			t.Fatalf("failed connect should retain reservation claim for reconciliation")
		}
		if claim.Status != "launching" || claim.LaunchStartedAt.IsZero() {
			t.Fatalf("claim=%+v want launching with launch_started_at", claim)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 1 || cmds[0][0] != "client-vpn-up" {
			t.Fatalf("failed connect commands=%v want single client-vpn-up", cmds)
		}
	})
}

func TestHandleSetProfileNormalizationAndValidation(t *testing.T) {
	svc, logPath := newFakeService(t, false)
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-set-profile-admin", "cosmos1setprofileadmin")

	code, payload := callJSONHandler(t, svc.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":" FAST ","session_token":"`+adminToken+`"}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["path_profile"].(string); got != "2hop" {
		t.Fatalf("path_profile=%q want=2hop", got)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "config-v1-set-profile" {
		t.Fatalf("unexpected commands for set_profile success: %v", cmds)
	}
	mustFlagValue(t, cmds[0], "--path-profile", "2hop")

	svc2, logPath2 := newFakeService(t, false)
	adminToken2 := seedGPMAdminTestSession(t, svc2, "gpm-set-profile-admin-2", "cosmos1setprofileadmin2")
	code, _ = callJSONHandler(t, svc2.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"bad","session_token":"`+adminToken2+`"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid profile status=%d want=%d", code, http.StatusBadRequest)
	}
	code, _ = callJSONHandler(t, svc2.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"2hop"}{"extra":1}`)
	if code != http.StatusBadRequest {
		t.Fatalf("trailing json status=%d want=%d", code, http.StatusBadRequest)
	}
	if cmds = readCommandLog(t, logPath2); len(cmds) != 0 {
		t.Fatalf("invalid set_profile should not execute commands, got=%v", cmds)
	}
}

func TestHandleUpdateGateAndForwarding(t *testing.T) {
	t.Run("gate disabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"origin",
			"branch":"main",
			"allow_dirty":true
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("update disabled should not execute commands, got=%v", cmds)
		}
	})

	t.Run("enabled forwards optional args", func(t *testing.T) {
		svc, logPath := newFakeService(t, true)
		adminToken := seedGPMAdminTestSession(t, svc, "gpm-update-admin", "cosmos1updateadmin")
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"upstream",
			"branch":"release/v1",
			"allow_dirty":false,
			"session_token":"`+adminToken+`"
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		cmds := readCommandLog(t, logPath)
		if len(cmds) != 1 || cmds[0][0] != "self-update" {
			t.Fatalf("unexpected update commands: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--show-status", "1")
		mustFlagValue(t, cmds[0], "--remote", "upstream")
		mustFlagValue(t, cmds[0], "--branch", "release/v1")
		mustFlagValue(t, cmds[0], "--allow-dirty", "0")
	})

	t.Run("invalid remote and branch are rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, true)
		adminToken := seedGPMAdminTestSession(t, svc, "gpm-update-invalid-admin", "cosmos1updateinvalidadmin")

		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"--upload-pack=sh",
			"branch":"main",
			"session_token":"`+adminToken+`"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid remote name") {
			t.Fatalf("error=%q want invalid remote message", got)
		}

		code, payload = callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"origin",
			"branch":"bad..branch",
			"session_token":"`+adminToken+`"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid branch name") {
			t.Fatalf("error=%q want invalid branch message", got)
		}

		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid update args should not execute commands, got=%v", cmds)
		}
	})

	t.Run("invalid json rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, true)
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{bad`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		code, payload = callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{"remote":"origin"}{"extra":1}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid update should not execute commands, got=%v", cmds)
		}
	})
}

func TestHandleStatusVariants(t *testing.T) {
	t.Run("json payload", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		statusMap, ok := payload["status"].(map[string]any)
		if !ok {
			t.Fatalf("status payload missing map: %v", payload)
		}
		if connected, _ := statusMap["connected"].(bool); !connected {
			t.Fatalf("status.connected=%v want=true", statusMap["connected"])
		}
		routing, ok := payload["routing"].(map[string]any)
		if !ok {
			t.Fatalf("routing payload missing map: %v", payload)
		}
		if got, _ := routing["source"].(string); got != "status_payload" {
			t.Fatalf("routing.source=%q want=status_payload", got)
		}
	})

	t.Run("raw payload fallback", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_STATUS_RAW", "1")

		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		statusMap, ok := payload["status"].(map[string]any)
		if !ok {
			t.Fatalf("status payload missing map: %v", payload)
		}
		if raw, _ := statusMap["raw"].(string); raw != "status-raw" {
			t.Fatalf("status.raw=%q want=status-raw", raw)
		}
	})

	t.Run("routing relay fallback detection", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_STATUS_JSON", `{
			"connected": true,
			"network": {
				"routing": {
					"path_mode": "managed-relay-fallback",
					"detail": "direct path unavailable; using managed relay"
				},
				"policy": {
					"direct_preferred": true
				}
			}
		}`)

		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		routing, ok := payload["routing"].(map[string]any)
		if !ok {
			t.Fatalf("routing payload missing map: %v", payload)
		}
		if got, _ := routing["mode"].(string); got != "relay_fallback" {
			t.Fatalf("routing.mode=%q want=relay_fallback payload=%v", got, routing)
		}
		if got, _ := routing["relay_fallback_active"].(bool); !got {
			t.Fatalf("routing.relay_fallback_active=%v want=true payload=%v", got, routing)
		}
		if got, _ := routing["direct_preferred"].(bool); !got {
			t.Fatalf("routing.direct_preferred=%v want=true payload=%v", got, routing)
		}
		if got, _ := routing["detail"].(string); got != "direct path unavailable; using managed relay" {
			t.Fatalf("routing.detail=%q want expected detail payload=%v", got, routing)
		}
		if got, _ := routing["source"].(string); got != "status_payload" {
			t.Fatalf("routing.source=%q want=status_payload payload=%v", got, routing)
		}
	})

	t.Run("routing direct detection", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_STATUS_JSON", `{
			"connected": true,
			"telemetry": {
				"route": {
					"connection_mode": "direct_mesh"
				},
				"preferences": {
					"prefer_direct": "true"
				}
			}
		}`)

		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		routing, ok := payload["routing"].(map[string]any)
		if !ok {
			t.Fatalf("routing payload missing map: %v", payload)
		}
		if got, _ := routing["mode"].(string); got != "direct" {
			t.Fatalf("routing.mode=%q want=direct payload=%v", got, routing)
		}
		if got, _ := routing["direct_preferred"].(bool); !got {
			t.Fatalf("routing.direct_preferred=%v want=true payload=%v", got, routing)
		}
		if got, _ := routing["relay_fallback_active"].(bool); got {
			t.Fatalf("routing.relay_fallback_active=%v want=false payload=%v", got, routing)
		}
		if got, _ := routing["source"].(string); got != "status_payload" {
			t.Fatalf("routing.source=%q want=status_payload payload=%v", got, routing)
		}
	})

	t.Run("command failure", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_STATUS_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "status command failed" {
			t.Fatalf("error=%q want=status command failed", got)
		}
	})
}

func TestHandleConfig(t *testing.T) {
	t.Run("success payload includes expected config hints", func(t *testing.T) {
		svc, _ := newFakeService(t, true)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = strongLocalAPIAuthToken
		svc.gpmConnectRequireSession = true
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmOperatorApprovalRequireSession = true
		svc.gpmOperatorApprovalRequireSessionSource = "production-default"
		svc.gpmAuthVerifyRequireCommand = true
		svc.gpmAuthVerifyRequireMetadata = true
		svc.gpmAuthVerifyRequireWalletExt = true
		svc.gpmAuthVerifyRequireCryptoProof = true
		svc.gpmAuthVerifyCommand = lifecycleSuccessCommand("verify-ok")
		svc.gpmConnectPolicyMode = "production"
		svc.gpmConnectPolicySource = "GPM_PRODUCTION_MODE"
		svc.gpmManifestTrustPolicyMode = "production"
		svc.gpmManifestTrustPolicySource = "GPM_PRODUCTION_MODE"
		svc.gpmManifestRequireHTTPS = true
		svc.gpmManifestRequireHTTPSSource = "production-default"
		svc.gpmManifestRequireSignature = true
		svc.gpmManifestRequireSigSource = "production-default"
		svc.gpmAuthVerifyPolicyMode = "production"
		svc.gpmAuthVerifyPolicySource = "GPM_PRODUCTION_MODE"
		svc.gpmAuthVerifyRequireCmdSource = "production-default"
		svc.gpmAuthVerifyMetadataSource = "production-default"
		svc.gpmAuthVerifyWalletExtSource = "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE"
		svc.gpmAuthVerifyCryptoSource = "GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF"
		svc.gpmAuthExpectedChainID = "gpm-testnet-1"
		svc.gpmAuthExpectedChainIDSource = "GPM_AUTH_VERIFY_EXPECTED_CHAIN_ID"
		svc.gpmAuthExpectedWalletHRP = "gpm"
		svc.gpmAuthExpectedWalletHRPSource = "GPM_AUTH_VERIFY_EXPECTED_WALLET_HRP"
		svc.gpmLegacyEnvAliasesActive = []string{
			"TDPN_PRODUCTION_MODE",
			"TDPN_AUTH_VERIFY_REQUIRE_METADATA",
		}
		svc.gpmLegacyEnvAliasWarnings = []string{
			"TDPN_PRODUCTION_MODE is deprecated; migrate to GPM_PRODUCTION_MODE",
			"TDPN_AUTH_VERIFY_REQUIRE_METADATA is deprecated; migrate to GPM_AUTH_VERIFY_REQUIRE_METADATA",
		}
		svc.gpmMainDomain = "https://gpm.example"
		svc.gpmManifestURL = "https://gpm.example/v1/bootstrap/manifest"
		svc.gpmManifestCache = ".easy-node-logs/gpm_manifest_cache.json"
		svc.gpmManifestMaxAge = 2 * time.Hour
		svc.gpmManifestRemoteRefreshIntvl = 15 * time.Minute
		svc.gpmManifestRemoteRefreshSrc = "TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC"
		svc.commandTimeout = 150 * time.Second

		code, payload := callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer " + strongLocalAPIAuthToken,
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		configMap, ok := payload["config"].(map[string]any)
		if !ok {
			t.Fatalf("config payload missing map: %v", payload)
		}
		if got, _ := configMap["connect_require_session"].(bool); !got {
			t.Fatalf("connect_require_session=%v want=true", configMap["connect_require_session"])
		}
		if got, _ := configMap["allow_legacy_connect_override"].(bool); got {
			t.Fatalf("allow_legacy_connect_override=%v want=false in production", configMap["allow_legacy_connect_override"])
		}
		if got, _ := configMap["gpm_production_mode"].(bool); !got {
			t.Fatalf("gpm_production_mode=%v want=true", configMap["gpm_production_mode"])
		}
		if got, _ := configMap["gpm_production_mode_source"].(string); got != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpm_production_mode_source=%q want=%q", got, "GPM_PRODUCTION_MODE")
		}
		if got, _ := configMap["connect_policy_mode"].(string); got != "production" {
			t.Fatalf("connect_policy_mode=%q want=%q", got, "production")
		}
		if got, _ := configMap["connect_policy_source"].(string); got != "GPM_PRODUCTION_MODE" {
			t.Fatalf("connect_policy_source=%q want=%q", got, "GPM_PRODUCTION_MODE")
		}
		if got, _ := configMap["gpm_operator_approval_require_session"].(bool); !got {
			t.Fatalf(
				"gpm_operator_approval_require_session=%v want=true",
				configMap["gpm_operator_approval_require_session"],
			)
		}
		if got, _ := configMap["gpm_operator_approval_require_session_policy_source"].(string); got != "production-default" {
			t.Fatalf(
				"gpm_operator_approval_require_session_policy_source=%q want=%q",
				got,
				"production-default",
			)
		}
		if got, _ := configMap["gpm_manifest_trust_policy_mode"].(string); got != "production" {
			t.Fatalf("gpm_manifest_trust_policy_mode=%q want=%q", got, "production")
		}
		if got, _ := configMap["gpm_manifest_trust_policy_source"].(string); got != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpm_manifest_trust_policy_source=%q want=%q", got, "GPM_PRODUCTION_MODE")
		}
		if got, _ := configMap["gpm_manifest_require_https"].(bool); !got {
			t.Fatalf("gpm_manifest_require_https=%v want=true", configMap["gpm_manifest_require_https"])
		}
		if got, _ := configMap["gpm_manifest_require_https_policy_source"].(string); got != "production-default" {
			t.Fatalf("gpm_manifest_require_https_policy_source=%q want=%q", got, "production-default")
		}
		if got, _ := configMap["gpm_manifest_require_signature"].(bool); !got {
			t.Fatalf("gpm_manifest_require_signature=%v want=true", configMap["gpm_manifest_require_signature"])
		}
		if got, _ := configMap["gpm_manifest_require_signature_policy_source"].(string); got != "production-default" {
			t.Fatalf("gpm_manifest_require_signature_policy_source=%q want=%q", got, "production-default")
		}
		if got, _ := configMap["gpm_auth_verify_policy_mode"].(string); got != "production" {
			t.Fatalf("gpm_auth_verify_policy_mode=%q want=%q", got, "production")
		}
		if got, _ := configMap["gpm_auth_verify_policy_source"].(string); got != "GPM_PRODUCTION_MODE" {
			t.Fatalf("gpm_auth_verify_policy_source=%q want=%q", got, "GPM_PRODUCTION_MODE")
		}
		if got, _ := configMap["gpm_auth_verify_require_command"].(bool); !got {
			t.Fatalf("gpm_auth_verify_require_command=%v want=true", configMap["gpm_auth_verify_require_command"])
		}
		if got, _ := configMap["gpm_auth_verify_require_command_policy_source"].(string); got != "production-default" {
			t.Fatalf("gpm_auth_verify_require_command_policy_source=%q want=%q", got, "production-default")
		}
		if got, _ := configMap["gpm_auth_verify_require_metadata"].(bool); !got {
			t.Fatalf("gpm_auth_verify_require_metadata=%v want=true", configMap["gpm_auth_verify_require_metadata"])
		}
		if got, _ := configMap["gpm_auth_verify_require_metadata_policy_source"].(string); got != "production-default" {
			t.Fatalf("gpm_auth_verify_require_metadata_policy_source=%q want=%q", got, "production-default")
		}
		if got, _ := configMap["gpm_auth_verify_require_wallet_extension"].(bool); !got {
			t.Fatalf("gpm_auth_verify_require_wallet_extension=%v want=true", configMap["gpm_auth_verify_require_wallet_extension"])
		}
		if got, _ := configMap["gpm_auth_verify_require_wallet_extension_source"].(bool); !got {
			t.Fatalf("gpm_auth_verify_require_wallet_extension_source=%v want=true", configMap["gpm_auth_verify_require_wallet_extension_source"])
		}
		if got, _ := configMap["gpm_auth_verify_require_wallet_extension_policy_source"].(string); got != "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE" {
			t.Fatalf("gpm_auth_verify_require_wallet_extension_policy_source=%q want=%q", got, "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE")
		}
		if got, _ := configMap["gpm_auth_verify_require_crypto_proof"].(bool); !got {
			t.Fatalf("gpm_auth_verify_require_crypto_proof=%v want=true", configMap["gpm_auth_verify_require_crypto_proof"])
		}
		if got, _ := configMap["gpm_auth_verify_require_crypto_proof_policy_source"].(string); got != "GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF" {
			t.Fatalf("gpm_auth_verify_require_crypto_proof_policy_source=%q want=%q", got, "GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF")
		}
		if got, _ := configMap["gpm_auth_verify_command_configured"].(bool); !got {
			t.Fatalf("gpm_auth_verify_command_configured=%v want=true", configMap["gpm_auth_verify_command_configured"])
		}
		if got, _ := configMap["gpm_auth_expected_chain_id"].(string); got != "gpm-testnet-1" {
			t.Fatalf("gpm_auth_expected_chain_id=%q want=gpm-testnet-1", got)
		}
		if got, _ := configMap["gpm_auth_expected_chain_id_source"].(string); got != "GPM_AUTH_VERIFY_EXPECTED_CHAIN_ID" {
			t.Fatalf("gpm_auth_expected_chain_id_source=%q want=GPM_AUTH_VERIFY_EXPECTED_CHAIN_ID", got)
		}
		if got, _ := configMap["gpm_auth_expected_wallet_hrp"].(string); got != "gpm" {
			t.Fatalf("gpm_auth_expected_wallet_hrp=%q want=gpm", got)
		}
		if got, _ := configMap["gpm_auth_expected_wallet_hrp_source"].(string); got != "GPM_AUTH_VERIFY_EXPECTED_WALLET_HRP" {
			t.Fatalf("gpm_auth_expected_wallet_hrp_source=%q want=GPM_AUTH_VERIFY_EXPECTED_WALLET_HRP", got)
		}
		if got, _ := configMap["gpm_main_domain"].(string); got != "https://gpm.example" {
			t.Fatalf("gpm_main_domain=%q want=%q", got, "https://gpm.example")
		}
		if got, _ := configMap["gpm_manifest_url"].(string); got != "https://gpm.example/v1/bootstrap/manifest" {
			t.Fatalf("gpm_manifest_url=%q want=%q", got, "https://gpm.example/v1/bootstrap/manifest")
		}
		if got, _ := configMap["gpm_manifest_cache_path"].(string); got != ".easy-node-logs/gpm_manifest_cache.json" {
			t.Fatalf("gpm_manifest_cache_path=%q want=%q", got, ".easy-node-logs/gpm_manifest_cache.json")
		}
		if got, _ := configMap["gpm_manifest_cache_max_age_sec"].(float64); int(got) != 7200 {
			t.Fatalf("gpm_manifest_cache_max_age_sec=%v want=7200", configMap["gpm_manifest_cache_max_age_sec"])
		}
		if got, _ := configMap["gpm_manifest_remote_refresh_interval_sec"].(float64); int(got) != 900 {
			t.Fatalf("gpm_manifest_remote_refresh_interval_sec=%v want=900", configMap["gpm_manifest_remote_refresh_interval_sec"])
		}
		if got, _ := configMap["gpm_manifest_remote_refresh_interval_source"].(string); got != "TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC" {
			t.Fatalf(
				"gpm_manifest_remote_refresh_interval_source=%q want=%q",
				got,
				"TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC",
			)
		}
		if got, _ := configMap["gpm_manifest_resolve_policy"].(string); got != "cache_first_bounded_remote_refresh" {
			t.Fatalf("gpm_manifest_resolve_policy=%q want=cache_first_bounded_remote_refresh", got)
		}
		if got, _ := configMap["gpm_manifest_resolve_policy_detail"].(string); !strings.Contains(got, "fall back to trusted cache") {
			t.Fatalf("gpm_manifest_resolve_policy_detail=%q want contains fallback detail", got)
		}
		if got, _ := configMap["gpm_legacy_env_aliases_active_count"].(float64); int(got) != 2 {
			t.Fatalf("gpm_legacy_env_aliases_active_count=%v want=2", configMap["gpm_legacy_env_aliases_active_count"])
		}
		activeAliasesRaw, ok := configMap["gpm_legacy_env_aliases_active"].([]any)
		if !ok {
			t.Fatalf("gpm_legacy_env_aliases_active missing array: %T %v", configMap["gpm_legacy_env_aliases_active"], configMap["gpm_legacy_env_aliases_active"])
		}
		if len(activeAliasesRaw) != 2 {
			t.Fatalf("gpm_legacy_env_aliases_active len=%d want=2 values=%v", len(activeAliasesRaw), activeAliasesRaw)
		}
		gotAliases := map[string]struct{}{}
		for _, raw := range activeAliasesRaw {
			value, _ := raw.(string)
			gotAliases[value] = struct{}{}
		}
		if _, ok := gotAliases["TDPN_PRODUCTION_MODE"]; !ok {
			t.Fatalf("gpm_legacy_env_aliases_active missing TDPN_PRODUCTION_MODE: %v", activeAliasesRaw)
		}
		if _, ok := gotAliases["TDPN_AUTH_VERIFY_REQUIRE_METADATA"]; !ok {
			t.Fatalf("gpm_legacy_env_aliases_active missing TDPN_AUTH_VERIFY_REQUIRE_METADATA: %v", activeAliasesRaw)
		}
		warningsRaw, ok := configMap["gpm_legacy_env_alias_warnings"].([]any)
		if !ok {
			t.Fatalf("gpm_legacy_env_alias_warnings missing array: %T %v", configMap["gpm_legacy_env_alias_warnings"], configMap["gpm_legacy_env_alias_warnings"])
		}
		if len(warningsRaw) != 2 {
			t.Fatalf("gpm_legacy_env_alias_warnings len=%d want=2 values=%v", len(warningsRaw), warningsRaw)
		}
		combinedWarning, _ := configMap["gpm_legacy_env_aliases_warning"].(string)
		if !strings.Contains(combinedWarning, "TDPN_PRODUCTION_MODE is deprecated; migrate to GPM_PRODUCTION_MODE") {
			t.Fatalf("gpm_legacy_env_aliases_warning missing production deprecation message: %q", combinedWarning)
		}
		if !strings.Contains(combinedWarning, "TDPN_AUTH_VERIFY_REQUIRE_METADATA is deprecated; migrate to GPM_AUTH_VERIFY_REQUIRE_METADATA") {
			t.Fatalf("gpm_legacy_env_aliases_warning missing metadata deprecation message: %q", combinedWarning)
		}
		if got, _ := configMap["command_timeout_sec"].(float64); int(got) != 150 {
			t.Fatalf("command_timeout_sec=%v want=150", configMap["command_timeout_sec"])
		}
		if got, _ := configMap["allow_update"].(bool); !got {
			t.Fatalf("allow_update=%v want=true", configMap["allow_update"])
		}
		if got, _ := configMap["allow_remote"].(bool); !got {
			t.Fatalf("allow_remote=%v want=true", configMap["allow_remote"])
		}
		if _, exists := configMap["auth_token"]; exists {
			t.Fatalf("auth_token must not be exposed: %v", configMap)
		}
		if _, exists := configMap["gpm_approval_token"]; exists {
			t.Fatalf("gpm_approval_token must not be exposed: %v", configMap)
		}
		if _, exists := configMap["gpm_manifest_hmac_key"]; exists {
			t.Fatalf("gpm_manifest_hmac_key must not be exposed: %v", configMap)
		}
	})

	t.Run("default payload reports production mode telemetry with defaults", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.authToken = "cfg-default-secret"
		svc.gpmConnectPolicyMode = ""
		svc.gpmConnectPolicySource = ""

		code, payload := callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer cfg-default-secret",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		configMap, ok := payload["config"].(map[string]any)
		if !ok {
			t.Fatalf("config payload missing map: %v", payload)
		}
		if got, _ := configMap["gpm_production_mode"].(bool); got {
			t.Fatalf("gpm_production_mode=%v want=false", configMap["gpm_production_mode"])
		}
		if got, _ := configMap["gpm_production_mode_source"].(string); got != "default" {
			t.Fatalf("gpm_production_mode_source=%q want=%q", got, "default")
		}
		if got, _ := configMap["connect_policy_mode"].(string); got != "default" {
			t.Fatalf("connect_policy_mode=%q want=%q", got, "default")
		}
		if got, _ := configMap["connect_policy_source"].(string); got != "default" {
			t.Fatalf("connect_policy_source=%q want=%q", got, "default")
		}
	})

	t.Run("invalid GPM_PRODUCTION_MODE env is reported as fail-closed production in config", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "invalid")
		t.Setenv("TDPN_PRODUCTION_MODE", "")

		svc := New()
		svc.authToken = "cfg-invalid-production-mode"

		code, payload := callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer cfg-invalid-production-mode",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		configMap, ok := payload["config"].(map[string]any)
		if !ok {
			t.Fatalf("config payload missing map: %v", payload)
		}
		if got, _ := configMap["gpm_production_mode"].(bool); !got {
			t.Fatalf("gpm_production_mode=%v want=true", configMap["gpm_production_mode"])
		}
		if got, _ := configMap["gpm_production_mode_source"].(string); got != "production-invalid-env-fail-closed" {
			t.Fatalf("gpm_production_mode_source=%q want=production-invalid-env-fail-closed", got)
		}
		if got, _ := configMap["connect_policy_mode"].(string); got != "production" {
			t.Fatalf("connect_policy_mode=%q want=production", got)
		}
		if got, _ := configMap["connect_policy_source"].(string); got != "production-invalid-env-fail-closed" {
			t.Fatalf("connect_policy_source=%q want=production-invalid-env-fail-closed", got)
		}
	})

	t.Run("production mode reports trusted-manifest binding policy source when exposed", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")

		svc := New()
		svc.authToken = "cfg-production-manual-binding-source"

		code, payload := callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer cfg-production-manual-binding-source",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		configMap, ok := payload["config"].(map[string]any)
		if !ok {
			t.Fatalf("config payload missing map: %v", payload)
		}
		if got, _ := configMap["gpm_legacy_connect_require_trusted_manifest_bootstrap"].(bool); !got {
			t.Fatalf("gpm_legacy_connect_require_trusted_manifest_bootstrap=%v want=true", configMap["gpm_legacy_connect_require_trusted_manifest_bootstrap"])
		}
		if got, _ := configMap["gpm_legacy_connect_require_trusted_manifest_bootstrap_policy_source"].(string); got != "production-default" {
			t.Fatalf("gpm_legacy_connect_require_trusted_manifest_bootstrap_policy_source=%q want=production-default", got)
		}
	})

	t.Run("production mode config reports invalid-env fail-closed source for trusted-manifest binding policy", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("TDPN_PRODUCTION_MODE", "")
		t.Setenv("GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "invalid")
		t.Setenv("TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP", "")

		svc := New()
		svc.authToken = "cfg-production-invalid-legacy-manifest-binding"

		code, payload := callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer cfg-production-invalid-legacy-manifest-binding",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		configMap, ok := payload["config"].(map[string]any)
		if !ok {
			t.Fatalf("config payload missing map: %v", payload)
		}
		if got, _ := configMap["gpm_legacy_connect_require_trusted_manifest_bootstrap"].(bool); !got {
			t.Fatalf("gpm_legacy_connect_require_trusted_manifest_bootstrap=%v want=true", configMap["gpm_legacy_connect_require_trusted_manifest_bootstrap"])
		}
		if got, _ := configMap["gpm_legacy_connect_require_trusted_manifest_bootstrap_policy_source"].(string); got != "production-invalid-env-fail-closed" {
			t.Fatalf("gpm_legacy_connect_require_trusted_manifest_bootstrap_policy_source=%q want=production-invalid-env-fail-closed", got)
		}
	})

	t.Run("method not allowed for non-get", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		code, payload := callJSONHandler(t, svc.handleConfig, http.MethodPost, "/v1/config", "")
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "method not allowed" {
			t.Fatalf("error=%q want=method not allowed", got)
		}
	})

	t.Run("auth required semantics match command-read policy", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = strongLocalAPIAuthToken

		code, payload := callJSONHandler(t, svc.handleConfig, http.MethodGet, "/v1/config", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("missing token status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "unauthorized" {
			t.Fatalf("error=%q want=unauthorized", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer " + strongLocalAPIAuthToken,
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})
}

func TestDiagnosticsAndDisconnectBasicCoverage(t *testing.T) {
	t.Run("diagnostics raw fallback", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_DIAG_RAW", "1")

		code, payload := callJSONHandler(t, svc.handleDiagnostics, http.MethodGet, "/v1/get_diagnostics", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		diagMap, ok := payload["diagnostics"].(map[string]any)
		if !ok {
			t.Fatalf("diagnostics payload missing map: %v", payload)
		}
		if raw, _ := diagMap["raw"].(string); raw != "diagnostics-raw" {
			t.Fatalf("diagnostics.raw=%q want=diagnostics-raw", raw)
		}
	})

	t.Run("disconnect failure mapping", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_DOWN_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "disconnect command failed" {
			t.Fatalf("error=%q want=disconnect command failed", got)
		}
	})
}

func TestServiceLifecycleMethodGuards(t *testing.T) {
	svc, _ := newFakeService(t, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
	}{
		{name: "service_status", handler: svc.handleServiceStatus, method: http.MethodPost, target: "/v1/service/status"},
		{name: "service_start", handler: svc.handleServiceStart, method: http.MethodGet, target: "/v1/service/start"},
		{name: "service_stop", handler: svc.handleServiceStop, method: http.MethodGet, target: "/v1/service/stop"},
		{name: "service_restart", handler: svc.handleServiceRestart, method: http.MethodGet, target: "/v1/service/restart"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, tc.method, tc.target, "")
			if code != http.StatusMethodNotAllowed {
				t.Fatalf("status=%d body=%v", code, payload)
			}
		})
	}
}

func TestHandleServiceStatusContract(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.serviceStatus = lifecycleSuccessCommand("service-running")
	svc.serviceStart = lifecycleSuccessCommand("service-start")
	svc.serviceRestart = lifecycleSuccessCommand("service-restart")

	code, payload := callJSONHandler(t, svc.handleServiceStatus, http.MethodGet, "/v1/service/status", "")
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}

	serviceMap, ok := payload["service"].(map[string]any)
	if !ok {
		t.Fatalf("service payload missing map: %v", payload)
	}
	if supported, _ := serviceMap["supported"].(bool); !supported {
		t.Fatalf("service.supported=%v want=true", serviceMap["supported"])
	}

	commandsMap, ok := serviceMap["commands"].(map[string]any)
	if !ok {
		t.Fatalf("service.commands missing map: %v", serviceMap)
	}
	if got, _ := commandsMap["status_configured"].(bool); !got {
		t.Fatalf("status_configured=%v want=true", commandsMap["status_configured"])
	}
	if got, _ := commandsMap["start_configured"].(bool); !got {
		t.Fatalf("start_configured=%v want=true", commandsMap["start_configured"])
	}
	if got, _ := commandsMap["stop_configured"].(bool); got {
		t.Fatalf("stop_configured=%v want=false", commandsMap["stop_configured"])
	}
	if got, _ := commandsMap["restart_configured"].(bool); !got {
		t.Fatalf("restart_configured=%v want=true", commandsMap["restart_configured"])
	}

	statusMap, ok := serviceMap["status"].(map[string]any)
	if !ok {
		t.Fatalf("service.status missing map: %v", serviceMap)
	}
	if got, _ := statusMap["ok"].(bool); !got {
		t.Fatalf("service.status.ok=%v want=true", statusMap["ok"])
	}
	if got, _ := statusMap["output"].(string); strings.TrimSpace(got) != "service-running" {
		t.Fatalf("service.status.output=%q want~service-running", got)
	}
	if got, _ := statusMap["rc"].(float64); int(got) != 0 {
		t.Fatalf("service.status.rc=%v want=0", statusMap["rc"])
	}
	if _, exists := serviceMap["status_error"]; exists {
		t.Fatalf("service.status_error should be absent on success: %v", serviceMap["status_error"])
	}
}

func TestServiceLifecycleMutationNotImplementedWhenUnset(t *testing.T) {
	svc, _ := newFakeService(t, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		target  string
		wantErr string
	}{
		{
			name:    "start_unset",
			handler: svc.handleServiceStart,
			target:  "/v1/service/start",
			wantErr: "service start not configured (set LOCAL_CONTROL_API_SERVICE_START_COMMAND)",
		},
		{
			name:    "stop_unset",
			handler: svc.handleServiceStop,
			target:  "/v1/service/stop",
			wantErr: "service stop not configured (set LOCAL_CONTROL_API_SERVICE_STOP_COMMAND)",
		},
		{
			name:    "restart_unset",
			handler: svc.handleServiceRestart,
			target:  "/v1/service/restart",
			wantErr: "service restart not configured (set LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.target, "")
			if code != http.StatusNotImplemented {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			if got, _ := payload["error"].(string); got != tc.wantErr {
				t.Fatalf("error=%q want=%q", got, tc.wantErr)
			}
		})
	}
}

func TestServiceLifecycleMutationSuccess(t *testing.T) {
	tests := []struct {
		name      string
		handlerFn func(*Service) http.HandlerFunc
		target    string
		action    string
		command   string
	}{
		{
			name:      "start_success",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStart },
			target:    "/v1/service/start",
			action:    "start",
			command:   "service-started",
		},
		{
			name:      "stop_success",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStop },
			target:    "/v1/service/stop",
			action:    "stop",
			command:   "service-stopped",
		},
		{
			name:      "restart_success",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceRestart },
			target:    "/v1/service/restart",
			action:    "restart",
			command:   "service-restarted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			switch tc.action {
			case "start":
				svc.serviceStart = lifecycleSuccessCommand(tc.command)
			case "stop":
				svc.serviceStop = lifecycleSuccessCommand(tc.command)
			case "restart":
				svc.serviceRestart = lifecycleSuccessCommand(tc.command)
			default:
				t.Fatalf("unknown action %q", tc.action)
			}

			code, payload := callJSONHandler(t, tc.handlerFn(svc), http.MethodPost, tc.target, "")
			if code != http.StatusOK {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			if got, _ := payload["action"].(string); got != tc.action {
				t.Fatalf("action=%q want=%q", got, tc.action)
			}
			if got, _ := payload["rc"].(float64); int(got) != 0 {
				t.Fatalf("rc=%v want=0", payload["rc"])
			}
			if got, _ := payload["output"].(string); got == "" {
				t.Fatalf("output should not be empty: %v", payload)
			}
			if got, _ := payload["note"].(string); !strings.Contains(got, "/v1/gpm/service/") {
				t.Fatalf("note=%q want gpm migration hint", got)
			}
		})
	}
}

func TestServiceLifecycleMutationFailureReturnsBadGateway(t *testing.T) {
	tests := []struct {
		name      string
		handlerFn func(*Service) http.HandlerFunc
		target    string
		action    string
		output    string
		exitCode  int
	}{
		{
			name:      "start_failure",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStart },
			target:    "/v1/service/start",
			action:    "start",
			output:    "start-failed",
			exitCode:  23,
		},
		{
			name:      "stop_failure",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStop },
			target:    "/v1/service/stop",
			action:    "stop",
			output:    "stop-failed",
			exitCode:  24,
		},
		{
			name:      "restart_failure",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceRestart },
			target:    "/v1/service/restart",
			action:    "restart",
			output:    "restart-failed",
			exitCode:  25,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			switch tc.action {
			case "start":
				svc.serviceStart = lifecycleFailureCommand(tc.output, tc.exitCode)
			case "stop":
				svc.serviceStop = lifecycleFailureCommand(tc.output, tc.exitCode)
			case "restart":
				svc.serviceRestart = lifecycleFailureCommand(tc.output, tc.exitCode)
			default:
				t.Fatalf("unknown action %q", tc.action)
			}

			code, payload := callJSONHandler(t, tc.handlerFn(svc), http.MethodPost, tc.target, "")
			if code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			if got, _ := payload["action"].(string); got != tc.action {
				t.Fatalf("action=%q want=%q", got, tc.action)
			}
			if got, _ := payload["error"].(string); got != "service "+tc.action+" command failed" {
				t.Fatalf("error=%q want=%q", got, "service "+tc.action+" command failed")
			}
			if got, _ := payload["rc"].(float64); int(got) <= 0 {
				t.Fatalf("rc=%v want positive exit code", payload["rc"])
			}
			if got, _ := payload["output"].(string); !strings.Contains(got, tc.output) {
				t.Fatalf("output=%q want action failure marker", got)
			}
		})
	}
}

func TestServiceLifecycleMutationAuthRequired(t *testing.T) {
	t.Run("non-loopback requires configured token for lifecycle handlers", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.serviceStart = lifecycleSuccessCommand("start-ok")
		svc.serviceStop = lifecycleSuccessCommand("stop-ok")
		svc.serviceRestart = lifecycleSuccessCommand("restart-ok")

		tests := []struct {
			name    string
			handler http.HandlerFunc
			target  string
		}{
			{name: "start", handler: svc.handleServiceStart, target: "/v1/service/start"},
			{name: "stop", handler: svc.handleServiceStop, target: "/v1/service/stop"},
			{name: "restart", handler: svc.handleServiceRestart, target: "/v1/service/restart"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.target, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("valid bearer token allows lifecycle handlers", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = strongLocalAPIAuthToken
		svc.serviceStart = lifecycleSuccessCommand("start-ok")
		svc.serviceStop = lifecycleSuccessCommand("stop-ok")
		svc.serviceRestart = lifecycleSuccessCommand("restart-ok")

		tests := []struct {
			name    string
			handler http.HandlerFunc
			target  string
			action  string
		}{
			{name: "start", handler: svc.handleServiceStart, target: "/v1/service/start", action: "start"},
			{name: "stop", handler: svc.handleServiceStop, target: "/v1/service/stop", action: "stop"},
			{name: "restart", handler: svc.handleServiceRestart, target: "/v1/service/restart", action: "restart"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.target, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("missing token status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); got != "unauthorized" {
					t.Fatalf("error=%q want=unauthorized", got)
				}

				code, payload = callJSONHandlerWithHeaders(t, tc.handler, http.MethodPost, tc.target, "", map[string]string{
					"Authorization": "Bearer " + strongLocalAPIAuthToken,
				})
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["action"].(string); got != tc.action {
					t.Fatalf("action=%q want=%q", got, tc.action)
				}
			})
		}
	})
}

func TestServiceLifecycleMutationProductionGuard(t *testing.T) {
	t.Run("production blocks legacy lifecycle endpoint by default", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectPolicyMode = "production"
		svc.serviceRestart = lifecycleSuccessCommand("restart-ok")

		code, payload := callJSONHandler(t, svc.handleServiceRestart, http.MethodPost, "/v1/service/restart", "")
		if code != http.StatusForbidden {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "legacy service lifecycle endpoint is disabled") {
			t.Fatalf("error=%q want legacy lifecycle disabled payload=%v", got, payload)
		}
		if got, _ := payload["hint"].(string); !strings.Contains(got, "GPM_ALLOW_LEGACY_SERVICE_MUTATIONS=1") {
			t.Fatalf("hint=%q want break-glass env payload=%v", got, payload)
		}
		if data, err := os.ReadFile(logPath); err != nil {
			t.Fatalf("read fake script log: %v", err)
		} else if strings.TrimSpace(string(data)) != "" {
			t.Fatalf("legacy command executed despite production guard: %q", string(data))
		}
	})

	t.Run("production break glass still requires gpm lifecycle session", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmConnectPolicyMode = "production"
		svc.gpmAllowLegacyServiceMutations = true
		svc.serviceRestart = lifecycleSuccessCommand("restart-ok")

		code, payload := callJSONHandler(t, svc.handleServiceRestart, http.MethodPost, "/v1/service/restart", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d want missing session rejection payload=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session token is required") {
			t.Fatalf("error=%q want session token guidance payload=%v", got, payload)
		}

		token := seedGPMAdminTestSession(t, svc, "gpm-break-glass-admin", "cosmos1breakglassadmin")
		code, payload = callJSONHandler(t, svc.handleServiceRestart, http.MethodPost, "/v1/service/restart", `{"session_token":"`+token+`"}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["action"].(string); got != "restart" {
			t.Fatalf("action=%q want restart payload=%v", got, payload)
		}
		if got, _ := payload["note"].(string); !strings.Contains(got, "/v1/gpm/service/restart") {
			t.Fatalf("note=%q want GPM migration hint payload=%v", got, payload)
		}
	})
}

func TestGPMServiceLifecycleMutationSessionGate(t *testing.T) {
	t.Run("missing session token rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "session token is required" {
			t.Fatalf("error=%q want session-token-required", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-bad-token"}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "invalid or expired session" {
			t.Fatalf("error=%q want invalid-or-expired-session", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:         "gpm-expired-token",
			Role:          "operator",
			CreatedAt:     time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:     time.Now().UTC().Add(-time.Minute),
			WalletAddress: "cosmos1expired",
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-expired-token"}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "invalid or expired session" {
			t.Fatalf("error=%q want invalid-or-expired-session", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("expired token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("client role rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:         "gpm-client-token",
			Role:          "client",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
			WalletAddress: "cosmos1client",
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-client-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "operator or admin required") {
			t.Fatalf("error=%q want role gate message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("client role should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role without approved application rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-operator-pending-token",
			Role:                  "operator",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			WalletAddress:         "cosmos1operatorpending",
			ChainOperatorID:       "operator-pending-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatorpending",
			ChainOperatorID: "operator-pending-1",
			ServerLabel:     "pending-node",
			Status:          "pending",
			UpdatedAt:       time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-pending-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, `status "pending" is not approved`) {
			t.Fatalf("error=%q want pending-not-approved message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("operator without approved application should not execute commands, got=%v", cmds)
		}
	})

	t.Run("unbound operator role rejected before lifecycle mutation", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-operator-unbound-token",
			Role:            "operator",
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().UTC().Add(time.Hour),
			WalletAddress:   "cosmos1operatorunbound",
			ChainOperatorID: "operator-unbound-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatorunbound",
			ChainOperatorID: "operator-unbound-1",
			ServerLabel:     "approved-node",
			Status:          "approved",
			UpdatedAt:       time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-unbound-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound session") {
			t.Fatalf("error=%q want wallet-bound-session message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("unbound operator session should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role with approved application but missing session chain operator id rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-operator-approved-missing-session-chain-token",
			Role:                  "operator",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			WalletAddress:         "cosmos1operatormissingsessionchain",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatormissingsessionchain",
			ChainOperatorID: "operator-approved-missing-session-chain-1",
			ServerLabel:     "approved-node",
			Status:          "approved",
			UpdatedAt:       time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-approved-missing-session-chain-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "out of sync") {
			t.Fatalf("error=%q want out-of-sync message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("operator with incomplete chain binding should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role with approved application but missing approved chain operator id rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-operator-approved-missing-approved-chain-token",
			Role:                  "operator",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			WalletAddress:         "cosmos1operatormissingapprovedchain",
			ChainOperatorID:       "operator-approved-missing-approved-chain-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress: "cosmos1operatormissingapprovedchain",
			ServerLabel:   "approved-node",
			Status:        "approved",
			UpdatedAt:     time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-approved-missing-approved-chain-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "out of sync") {
			t.Fatalf("error=%q want out-of-sync message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("operator with incomplete chain binding should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role with approved application but mismatched chain operator ids rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-operator-approved-mismatch-chain-token",
			Role:                  "operator",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			WalletAddress:         "cosmos1operatormismatchchain",
			ChainOperatorID:       "operator-approved-mismatch-a",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatormismatchchain",
			ChainOperatorID: "operator-approved-mismatch-b",
			ServerLabel:     "approved-node",
			Status:          "approved",
			UpdatedAt:       time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-approved-mismatch-chain-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "out of sync") {
			t.Fatalf("error=%q want out-of-sync message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("operator with mismatched chain binding should not execute commands, got=%v", cmds)
		}
	})

	t.Run("production operator role with local approval evidence rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmConnectPolicyMode = "production"
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-operator-local-approval-token",
			Role:                  "operator",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
			WalletAddress:         "cosmos1operatorlocalapproval",
			ChainOperatorID:       "operator-local-approval",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:          "cosmos1operatorlocalapproval",
			ChainOperatorID:        "operator-local-approval",
			ServerLabel:            "approved-node",
			Status:                 "approved",
			ApprovalEvidenceSource: "admin_session",
			UpdatedAt:              time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-local-approval-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "chain-governance approval evidence") {
			t.Fatalf("error=%q want production approval evidence message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("operator with local-only approval evidence should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role with approved application executes legacy lifecycle command", func(t *testing.T) {
		const lifecycleCommand = "go version"
		tests := []struct {
			name      string
			handlerFn func(*Service) http.HandlerFunc
			target    string
			command   string
		}{
			{name: "start", handlerFn: func(s *Service) http.HandlerFunc { return s.handleGPMServiceStart }, target: "/v1/gpm/service/start", command: lifecycleCommand},
			{name: "stop", handlerFn: func(s *Service) http.HandlerFunc { return s.handleGPMServiceStop }, target: "/v1/gpm/service/stop", command: lifecycleCommand},
			{name: "restart", handlerFn: func(s *Service) http.HandlerFunc { return s.handleGPMServiceRestart }, target: "/v1/gpm/service/restart", command: lifecycleCommand},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				svc, _ := newFakeService(t, false)
				svc.gpmState = newGPMRuntimeState()
				switch tc.name {
				case "start":
					svc.serviceStart = tc.command
				case "stop":
					svc.serviceStop = tc.command
				case "restart":
					svc.serviceRestart = tc.command
				}
				svc.gpmState.putSession(gpmSession{
					Token:                 "gpm-operator-token",
					Role:                  "operator",
					WalletBindingVerified: true,
					CreatedAt:             time.Now().UTC(),
					ExpiresAt:             time.Now().UTC().Add(time.Hour),
					WalletAddress:         "cosmos1operator",
					ChainOperatorID:       "operator-approved-1",
				})
				svc.gpmState.upsertOperator(gpmOperatorApplication{
					WalletAddress:   "cosmos1operator",
					ChainOperatorID: "operator-approved-1",
					ServerLabel:     "approved-node",
					Status:          "approved",
					UpdatedAt:       time.Now().UTC(),
				})

				code, payload := callJSONHandler(t, tc.handlerFn(svc), http.MethodPost, tc.target, `{"session_token":"gpm-operator-token"}`)
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["action"].(string); got != tc.name {
					t.Fatalf("action=%q want=%q", got, tc.name)
				}
				if got, _ := payload["rc"].(float64); int(got) != 0 {
					t.Fatalf("rc=%v want=0", payload["rc"])
				}
				if got, _ := payload["output"].(string); got == "" {
					t.Fatalf("output should not be empty: %v", payload)
				}
			})
		}
	})

	t.Run("admin role also executes lifecycle command", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceRestart = "go version"
		svc.gpmState.putSession(gpmSession{
			Token:                  "gpm-admin-token",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              time.Now().UTC(),
			ExpiresAt:              time.Now().UTC().Add(time.Hour),
			WalletAddress:          "cosmos1admin",
		})
		trustGPMAdminTestPolicy(svc, "cosmos1admin")

		code, payload := callJSONHandler(t, svc.handleGPMServiceRestart, http.MethodPost, "/v1/gpm/service/restart", `{"session_token":"gpm-admin-token"}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["action"].(string); got != "restart" {
			t.Fatalf("action=%q want=restart", got)
		}
		if got, _ := payload["output"].(string); got == "" {
			t.Fatalf("output should not be empty: %v", payload)
		}
	})
}

func TestGPMAdminSurfacesRejectUnboundAdminSessions(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:          "gpm-unbound-admin-token",
		WalletAddress:  "cosmos1unboundadmin",
		WalletProvider: "keplr",
		Role:           "admin",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
		body    string
		headers map[string]string
	}{
		{
			name:    "audit_recent",
			handler: svc.handleGPMAuditRecent,
			method:  http.MethodGet,
			target:  "/v1/gpm/audit/recent",
			headers: map[string]string{"X-GPM-Session-Token": "gpm-unbound-admin-token"},
		},
		{
			name:    "gap_summary",
			handler: svc.handleGPMGapSummary,
			method:  http.MethodGet,
			target:  "/v1/gpm/gaps/summary",
			headers: map[string]string{"X-GPM-Session-Token": "gpm-unbound-admin-token"},
		},
		{
			name:    "admin_contribution_list",
			handler: svc.handleGPMAdminContributionList,
			method:  http.MethodPost,
			target:  "/v1/gpm/admin/contributions/list",
			body:    `{"session_token":"gpm-unbound-admin-token"}`,
		},
		{
			name:    "admin_reward_review",
			handler: svc.handleGPMAdminRewardReview,
			method:  http.MethodPost,
			target:  "/v1/gpm/admin/rewards/review",
			body:    `{"session_token":"gpm-unbound-admin-token","wallet_address":"cosmos1reward"}`,
		},
		{
			name:    "admin_reward_hold",
			handler: svc.handleGPMAdminRewardHold,
			method:  http.MethodPost,
			target:  "/v1/gpm/admin/rewards/hold",
			body:    `{"session_token":"gpm-unbound-admin-token","wallet_address":"cosmos1reward","action":"hold","reason":"test"}`,
		},
		{
			name:    "operator_list",
			handler: svc.handleGPMOperatorList,
			method:  http.MethodPost,
			target:  "/v1/gpm/onboarding/operator/list",
			body:    `{"session_token":"gpm-unbound-admin-token"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandlerWithHeaders(t, tc.handler, tc.method, tc.target, tc.body, tc.headers)
			if code != http.StatusForbidden {
				t.Fatalf("status=%d payload=%v", code, payload)
			}
			if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound admin session") {
				t.Fatalf("error=%q want wallet-bound admin session payload=%v", got, payload)
			}
		})
	}
}

func TestGPMAdminSurfacesRevalidateCurrentAdminPolicy(t *testing.T) {
	t.Run("rejects admin session when wallet is no longer allowlisted", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		token := seedGPMAdminTestSession(t, svc, "gpm-admin-stale-allowlist-token", "cosmos1staleadmin")
		svc.gpmAdminWalletAllowlist = map[string]struct{}{}

		code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "", map[string]string{"X-GPM-Session-Token": token})
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "allowlisted") {
			t.Fatalf("error=%q want allowlist revalidation message payload=%v", got, payload)
		}
	})

	t.Run("rejects legacy persisted admin session without command verification source", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-admin-legacy-source-token",
			WalletAddress:         "cosmos1legacyadmin",
			WalletProvider:        "keplr",
			Role:                  "admin",
			WalletBindingVerified: true,
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1legacyadmin")

		code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "", map[string]string{"X-GPM-Session-Token": "gpm-admin-legacy-source-token"})
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "command-backed wallet-bound admin session") {
			t.Fatalf("error=%q want command-backed source revalidation message payload=%v", got, payload)
		}
	})
}

func TestMethodGuards(t *testing.T) {
	svc, _ := newFakeService(t, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
	}{
		{name: "health", handler: svc.handleHealth, method: http.MethodPost, target: "/v1/health"},
		{name: "status", handler: svc.handleStatus, method: http.MethodPost, target: "/v1/status"},
		{name: "connect", handler: svc.handleConnect, method: http.MethodGet, target: "/v1/connect"},
		{name: "disconnect", handler: svc.handleDisconnect, method: http.MethodGet, target: "/v1/disconnect"},
		{name: "set_profile", handler: svc.handleSetProfile, method: http.MethodGet, target: "/v1/set_profile"},
		{name: "diagnostics", handler: svc.handleDiagnostics, method: http.MethodPost, target: "/v1/get_diagnostics"},
		{name: "update", handler: svc.handleUpdate, method: http.MethodGet, target: "/v1/update"},
		{name: "gpm_service_start", handler: svc.handleGPMServiceStart, method: http.MethodGet, target: "/v1/gpm/service/start"},
		{name: "gpm_service_stop", handler: svc.handleGPMServiceStop, method: http.MethodGet, target: "/v1/gpm/service/stop"},
		{name: "gpm_service_restart", handler: svc.handleGPMServiceRestart, method: http.MethodGet, target: "/v1/gpm/service/restart"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, tc.method, tc.target, "")
			if code != http.StatusMethodNotAllowed {
				t.Fatalf("status=%d body=%v", code, payload)
			}
		})
	}
}

func TestMutationAuthGuard(t *testing.T) {
	t.Run("loopback without token requires auth by default", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = false
		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
			t.Fatalf("error=%q want token-not-configured", got)
		}
	})

	t.Run("loopback without token allows developer mode when explicitly enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "127.0.0.1:8095"
		svc.allowUnauthLoopback = true
		code, payload := callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "http://127.0.0.1:8095",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "",
		})
		if code != http.StatusForbidden {
			t.Fatalf("expected missing origin to be blocked, got status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "cross-origin mutation blocked in unauthenticated loopback mode" {
			t.Fatalf("error=%q want=cross-origin mutation blocked in unauthenticated loopback mode", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "http://localhost:3000",
		})
		if code != http.StatusForbidden {
			t.Fatalf("expected cross-origin localhost:3000 to be blocked, got status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "cross-origin mutation blocked in unauthenticated loopback mode" {
			t.Fatalf("error=%q want=cross-origin mutation blocked in unauthenticated loopback mode", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "http://127.0.0.1:8095",
		})
		if code != http.StatusOK {
			t.Fatalf("expected same-origin loopback mutation to pass, got status=%d body=%v", code, payload)
		}
	})

	t.Run("non-loopback requires configured token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
			t.Fatalf("error=%q want token-not-configured", got)
		}
	})

	t.Run("non-loopback returns 401 for every mutating endpoint when token is unset", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
			body    string
		}{
			{name: "connect", handler: svc.handleConnect, path: "/v1/connect", body: `{"bootstrap_directory":"http://dir.example:8081","invite_key":"inv"}`},
			{name: "disconnect", handler: svc.handleDisconnect, path: "/v1/disconnect", body: ""},
			{name: "set_profile", handler: svc.handleSetProfile, path: "/v1/set_profile", body: `{"path_profile":"2hop"}`},
			{name: "update", handler: svc.handleUpdate, path: "/v1/update", body: `{}`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.path, tc.body)
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("non-loopback rejects weak configured bearer tokens before mutation", func(t *testing.T) {
		weakTokens := []string{
			"token",
			"default-token",
			"secret-token",
			"change-me",
			"short-random-token-123",
		}
		for _, weakToken := range weakTokens {
			t.Run(weakToken, func(t *testing.T) {
				svc, _ := newFakeService(t, false)
				svc.addr = "0.0.0.0:8095"
				svc.authToken = weakToken

				code, payload := callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
					"Authorization": "Bearer " + weakToken,
				})
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "too weak") {
					t.Fatalf("error=%q want weak-token rejection", got)
				}
			})
		}
	})

	t.Run("non-loopback rejects missing or invalid bearer token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = strongLocalAPIAuthToken

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "unauthorized" {
			t.Fatalf("error=%q want=unauthorized", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer wrong-token",
		})
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})

	t.Run("non-loopback accepts valid bearer token on mutating endpoints", func(t *testing.T) {
		svc, _ := newFakeService(t, true)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = strongLocalAPIAuthToken
		adminToken := seedGPMAdminTestSession(t, svc, "gpm-bearer-admin", "cosmos1beareradmin")

		code, payload := callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer " + strongLocalAPIAuthToken,
		})
		if code != http.StatusOK {
			t.Fatalf("disconnect status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"2hop","session_token":"`+adminToken+`"}`, map[string]string{
			"Authorization": "Bearer " + strongLocalAPIAuthToken,
		})
		if code != http.StatusOK {
			t.Fatalf("set_profile status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{"session_token":"`+adminToken+`"}`, map[string]string{
			"Authorization": "Bearer " + strongLocalAPIAuthToken,
		})
		if code != http.StatusOK {
			t.Fatalf("update status=%d body=%v", code, payload)
		}
	})

	t.Run("loopback requires auth when token configured", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.authToken = "loopback-secret"

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "unauthorized" {
			t.Fatalf("error=%q want=unauthorized", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer loopback-secret",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})

	t.Run("read-only endpoints stay open when auth token is configured", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.authToken = "readonly-secret"

		code, payload := callJSONHandler(t, svc.handleHealth, http.MethodGet, "/v1/health", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})
}

func TestCommandReadAuthGuard(t *testing.T) {
	t.Run("loopback unauth mode blocks cross-origin command reads", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "127.0.0.1:8095"
		svc.allowUnauthLoopback = true

		code, payload := callJSONHandlerWithHeaders(t, svc.handleStatus, http.MethodGet, "/v1/status", "", map[string]string{
			"Origin": "",
		})
		if code != http.StatusForbidden {
			t.Fatalf("expected missing origin to be blocked, got status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "cross-origin command read blocked in unauthenticated loopback mode" {
			t.Fatalf("error=%q want=cross-origin command read blocked in unauthenticated loopback mode", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleStatus, http.MethodGet, "/v1/status", "", map[string]string{
			"Origin": "http://127.0.0.1:8095",
		})
		if code != http.StatusOK {
			t.Fatalf("expected same-origin command read to pass, got status=%d body=%v", code, payload)
		}
	})
}

func TestCommandBackedReadAuthGuard(t *testing.T) {
	t.Run("loopback without token requires auth by default", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = false
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("loopback command-backed reads stay open only in explicit developer mode", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = true
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
			})
		}
	})

	t.Run("non-loopback requires configured token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("valid bearer token allows command-backed reads on non-loopback", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = strongLocalAPIAuthToken
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("missing token status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); got != "unauthorized" {
					t.Fatalf("error=%q want=unauthorized", got)
				}

				code, payload = callJSONHandlerWithHeaders(t, tc.handler, http.MethodGet, tc.path, "", map[string]string{
					"Authorization": "Bearer " + strongLocalAPIAuthToken,
				})
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
			})
		}
	})
}

func TestParseBearerToken(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "valid bearer", raw: "Bearer abc123", want: "abc123"},
		{name: "valid lowercase", raw: "bearer token-1", want: "token-1"},
		{name: "missing token", raw: "Bearer", want: ""},
		{name: "wrong scheme", raw: "Basic abc", want: ""},
		{name: "extra fields", raw: "Bearer a b", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBearerToken(tc.raw); got != tc.want {
				t.Fatalf("parseBearerToken(%q)=%q want=%q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestConstantTimeTokenEqual(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		provided string
		want     bool
	}{
		{name: "exact match", expected: "secret-token", provided: "secret-token", want: true},
		{name: "different value same length", expected: "secret-token", provided: "secret-tokfn", want: false},
		{name: "length mismatch", expected: "secret-token", provided: "secret", want: false},
		{name: "empty expected", expected: "", provided: "secret-token", want: false},
		{name: "empty provided", expected: "secret-token", provided: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := constantTimeTokenEqual(tc.expected, tc.provided); got != tc.want {
				t.Fatalf("constantTimeTokenEqual(%q,%q)=%t want=%t", tc.expected, tc.provided, got, tc.want)
			}
		})
	}
}

func TestWriteJSONSetsNoStoreHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{"ok": true})
	res := rec.Result()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q want=no-store", got)
	}
	if got := res.Header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma=%q want=no-cache", got)
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q want=nosniff", got)
	}
}

func TestIsAllowedVPNInterfaceName(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		allow bool
	}{
		{name: "default", iface: "wgvpn0", allow: true},
		{name: "with punctuation", iface: "wg-localapi_1", allow: true},
		{name: "wrong prefix", iface: "eth0", allow: false},
		{name: "too long", iface: "wg12345678901234", allow: false},
		{name: "empty", iface: "", allow: false},
		{name: "invalid character", iface: "wg;rm", allow: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedVPNInterfaceName(tc.iface)
			if got != tc.allow {
				t.Fatalf("isAllowedVPNInterfaceName(%q)=%t want=%t", tc.iface, got, tc.allow)
			}
		})
	}
}

func TestUpdateOmitOptionalFlagsWhenUnset(t *testing.T) {
	svc, logPath := newFakeService(t, true)
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-update-omit-admin", "cosmos1updateomitadmin")
	code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{"session_token":"`+adminToken+`"}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "self-update" {
		t.Fatalf("unexpected update commands: %v", cmds)
	}
	mustFlagValue(t, cmds[0], "--show-status", "1")
	mustNotHaveFlag(t, cmds[0], "--remote")
	mustNotHaveFlag(t, cmds[0], "--branch")
	mustNotHaveFlag(t, cmds[0], "--allow-dirty")
}

func TestLoadConnectDefaultsFromEnvFallback(t *testing.T) {
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
	t.Setenv("CLIENT_PATH_PROFILE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
	t.Setenv("CLIENT_WG_INTERFACE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "")
	t.Setenv("SIMPLE_CLIENT_RUN_PREFLIGHT", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")
	t.Setenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT", "")

	got := loadConnectDefaultsFromEnv()
	if got.pathProfile != "2hop" {
		t.Fatalf("pathProfile=%q want 2hop", got.pathProfile)
	}
	if got.interfaceName != "wgvpn0" {
		t.Fatalf("interfaceName=%q want wgvpn0", got.interfaceName)
	}
	if !got.runPreflight {
		t.Fatalf("runPreflight=%t want true", got.runPreflight)
	}
	if got.prodMode != "0" {
		t.Fatalf("prodMode=%q want 0", got.prodMode)
	}
	if defaultProdProfileForMode(got.prodMode, "2hop") {
		t.Fatalf("expected non-prod default when mode is 0")
	}
}

func TestLoadConnectDefaultsFromEnvConfigV1Mapping(t *testing.T) {
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
	t.Setenv("CLIENT_PATH_PROFILE", "3hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
	t.Setenv("CLIENT_WG_INTERFACE", "wgvpn9")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "0")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "auto")

	got := loadConnectDefaultsFromEnv()
	if got.pathProfile != "3hop" {
		t.Fatalf("pathProfile=%q want 3hop", got.pathProfile)
	}
	if got.interfaceName != "wgvpn9" {
		t.Fatalf("interfaceName=%q want wgvpn9", got.interfaceName)
	}
	if got.runPreflight {
		t.Fatalf("runPreflight=%t want false", got.runPreflight)
	}
	if got.prodMode != "auto" {
		t.Fatalf("prodMode=%q want auto", got.prodMode)
	}
	if !defaultProdProfileForMode(got.prodMode, "3hop") {
		t.Fatalf("expected auto mode to default prod on for 3hop")
	}
	if defaultProdProfileForMode(got.prodMode, "1hop") {
		t.Fatalf("expected auto mode to keep 1hop non-prod")
	}
}

func TestLoadConnectDefaultsFromEnvOverridePriority(t *testing.T) {
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "1hop")
	t.Setenv("CLIENT_PATH_PROFILE", "3hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "wg-localapi")
	t.Setenv("CLIENT_WG_INTERFACE", "wgvpn9")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "")
	t.Setenv("SIMPLE_CLIENT_RUN_PREFLIGHT", "0")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")
	t.Setenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT", "1")

	got := loadConnectDefaultsFromEnv()
	if got.pathProfile != "1hop" {
		t.Fatalf("pathProfile=%q want 1hop", got.pathProfile)
	}
	if got.interfaceName != "wg-localapi" {
		t.Fatalf("interfaceName=%q want wg-localapi", got.interfaceName)
	}
	if got.runPreflight {
		t.Fatalf("runPreflight=%t want false", got.runPreflight)
	}
	if got.prodMode != "1" {
		t.Fatalf("prodMode=%q want 1", got.prodMode)
	}
}

func TestResolveConnectOptionsDefaults(t *testing.T) {
	defaults := connectDefaults{
		pathProfile:   "3hop",
		interfaceName: "wgvpn9",
		runPreflight:  false,
		prodMode:      "auto",
	}
	got := resolveConnectOptions(connectRequest{}, defaults)
	if got.profile != "3hop" {
		t.Fatalf("profile=%q want 3hop", got.profile)
	}
	if got.interfaceName != "wgvpn9" {
		t.Fatalf("interfaceName=%q want wgvpn9", got.interfaceName)
	}
	if got.discoveryWaitSec != defaultDiscoveryWaitSec {
		t.Fatalf("discoveryWaitSec=%d want %d", got.discoveryWaitSec, defaultDiscoveryWaitSec)
	}
	if got.readyTimeoutSec != defaultReadyTimeoutSec {
		t.Fatalf("readyTimeoutSec=%d want %d", got.readyTimeoutSec, defaultReadyTimeoutSec)
	}
	if got.runPreflight {
		t.Fatalf("runPreflight=%t want false", got.runPreflight)
	}
	if !got.prodProfile {
		t.Fatalf("prodProfile=%t want true", got.prodProfile)
	}
	if got.installRoute {
		t.Fatalf("installRoute=%t want false", got.installRoute)
	}
	if got.installRouteIsSet {
		t.Fatalf("installRouteIsSet=%t want false", got.installRouteIsSet)
	}
}

func TestResolveConnectOptionsRequestOverridesDefaults(t *testing.T) {
	defaults := connectDefaults{
		pathProfile:   "3hop",
		interfaceName: "wgvpn9",
		runPreflight:  false,
		prodMode:      "0",
	}
	runPreflight := true
	prodProfile := true
	installRoute := true
	got := resolveConnectOptions(connectRequest{
		PathProfile:      "1hop",
		Interface:        "wgx0",
		DiscoveryWaitSec: 11,
		ReadyTimeoutSec:  21,
		RunPreflight:     &runPreflight,
		ProdProfile:      &prodProfile,
		InstallRoute:     &installRoute,
	}, defaults)
	if got.profile != "1hop" {
		t.Fatalf("profile=%q want 1hop", got.profile)
	}
	if got.interfaceName != "wgx0" {
		t.Fatalf("interfaceName=%q want wgx0", got.interfaceName)
	}
	if got.discoveryWaitSec != 11 {
		t.Fatalf("discoveryWaitSec=%d want 11", got.discoveryWaitSec)
	}
	if got.readyTimeoutSec != 21 {
		t.Fatalf("readyTimeoutSec=%d want 21", got.readyTimeoutSec)
	}
	if !got.runPreflight {
		t.Fatalf("runPreflight=%t want true", got.runPreflight)
	}
	if !got.prodProfile {
		t.Fatalf("prodProfile=%t want true", got.prodProfile)
	}
	if !got.installRoute {
		t.Fatalf("installRoute=%t want true", got.installRoute)
	}
	if !got.installRouteIsSet {
		t.Fatalf("installRouteIsSet=%t want true", got.installRouteIsSet)
	}
}

func TestDeriveConnectPolicyOneHopKeepsNonProd(t *testing.T) {
	options := resolvedConnectOptions{
		profile:           "1hop",
		prodProfile:       true,
		installRoute:      true,
		installRouteIsSet: false,
	}
	got := deriveConnectPolicy(options)
	if got.prodFlag != 0 {
		t.Fatalf("prodFlag=%d want 0", got.prodFlag)
	}
	if got.betaProfile != 0 {
		t.Fatalf("betaProfile=%d want 0", got.betaProfile)
	}
	if got.installRoute {
		t.Fatalf("installRoute=%t want false for one-hop default", got.installRoute)
	}
}

func TestRunEasyNodeTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "timeout.sh")
	script := "#!/usr/bin/env bash\nset -euo pipefail\nsleep 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write timeout script: %v", err)
	}

	svc := &Service{
		scriptPath:     scriptPath,
		commandTimeout: 50 * time.Millisecond,
	}
	out, rc, err := svc.runEasyNode(context.Background(), "ignored")
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if rc != 124 {
		t.Fatalf("timeout rc=%d want=124", rc)
	}
	if out != "" {
		t.Fatalf("timeout output=%q want empty", out)
	}
}

func TestRunEasyNodeFailsWhenScriptPathUnavailable(t *testing.T) {
	svc := &Service{
		commandTimeout: 2 * time.Second,
	}
	out, rc, err := svc.runEasyNode(context.Background(), "client-vpn-status", "--show-json", "1")
	if err == nil {
		t.Fatalf("expected unavailable script path error, got nil")
	}
	if rc != 127 {
		t.Fatalf("rc=%d want=127", rc)
	}
	if out != "" {
		t.Fatalf("out=%q want empty", out)
	}
	if !strings.Contains(err.Error(), "LOCAL_CONTROL_API_SCRIPT") {
		t.Fatalf("error=%q want LOCAL_CONTROL_API_SCRIPT guidance", err.Error())
	}
}

func TestRunEasyNodeSaturationReturnsConcurrencyError(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.maxConcurrentCmds = 1
	svc.commandSlots = make(chan struct{}, 1)
	svc.commandSlots <- struct{}{}

	out, rc, err := svc.runEasyNode(context.Background(), "client-vpn-status", "--show-json", "1")
	if err == nil {
		t.Fatalf("expected saturation error, got nil")
	}
	if !errors.Is(err, errCommandConcurrencySaturated) {
		t.Fatalf("expected saturation sentinel, got %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d want=0 for pre-exec saturation", rc)
	}
	if out != "" {
		t.Fatalf("out=%q want empty for pre-exec saturation", out)
	}
}

func TestRunEasyNodeTruncatesOversizedOutput(t *testing.T) {
	svc, _ := newFakeService(t, false)
	t.Setenv("LOCALAPI_TEST_OUTPUT_BYTES", strconv.Itoa(maxCommandOutputBytes+4096))

	out, rc, err := svc.runEasyNode(context.Background(), "client-vpn-status", "--show-json", "1")
	if err != nil {
		t.Fatalf("runEasyNode returned error: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d want=0", rc)
	}
	if !strings.Contains(out, "[output truncated to ") {
		t.Fatalf("expected truncated marker, out=%q", out)
	}
	if len(out) <= maxCommandOutputBytes {
		t.Fatalf("expected marker beyond capped payload, len(out)=%d cap=%d", len(out), maxCommandOutputBytes)
	}
	if len(out) > maxCommandOutputBytes+128 {
		t.Fatalf("expected bounded output length, got len=%d", len(out))
	}
}

func TestRunLifecycleCommandTruncatesOversizedOutput(t *testing.T) {
	svc := &Service{
		commandTimeout:    2 * time.Second,
		maxConcurrentCmds: 1,
		commandSlots:      make(chan struct{}, 1),
	}
	out, rc, err := svc.runLifecycleCommand(context.Background(), lifecycleOversizedOutputCommand())
	if err != nil {
		t.Fatalf("runLifecycleCommand returned error: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d want=0", rc)
	}
	if !strings.Contains(out, "[output truncated to ") {
		t.Fatalf("expected truncated marker, out=%q", out)
	}
	if len(out) > maxCommandOutputBytes+128 {
		t.Fatalf("expected bounded output length, got len=%d", len(out))
	}
}

func TestCommandBackedHandlersReturn429WhenConcurrencySaturated(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.serviceStart = "echo start-ok"
	svc.maxConcurrentCmds = 1
	svc.commandSlots = make(chan struct{}, 1)
	svc.commandSlots <- struct{}{}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		body    string
	}{
		{name: "status", handler: svc.handleStatus, method: http.MethodGet, path: "/v1/status"},
		{name: "disconnect", handler: svc.handleDisconnect, method: http.MethodPost, path: "/v1/disconnect"},
		{name: "service_start", handler: svc.handleServiceStart, method: http.MethodPost, path: "/v1/service/start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, tc.method, tc.path, tc.body)
			if code != http.StatusTooManyRequests {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			msg, _ := payload["error"].(string)
			if !strings.Contains(msg, "command concurrency limit reached") {
				t.Fatalf("error=%q want concurrency limit message", msg)
			}
		})
	}
}

func TestIsLoopbackBindAddrAllowsLiteralLoopbackAndLocalhostOnly(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}

	if !isLoopbackBindAddr("localhost:8095") {
		t.Fatal("expected localhost bind to be allowed without DNS trust")
	}
	if !isLoopbackBindAddr("127.0.0.1:8095") {
		t.Fatal("expected literal IPv4 loopback bind to be allowed")
	}
	if !isLoopbackBindAddr("[::1]:8095") {
		t.Fatal("expected literal IPv6 loopback bind to be allowed")
	}
	if isLoopbackBindAddr("rebind.example:8095") {
		t.Fatal("expected DNS-resolved loopback hostname bind to be rejected")
	}
}

func TestIsAllowedUnauthLoopbackOriginAllowsLiteralLoopbackAndLocalhostOnly(t *testing.T) {
	if !isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://localhost:8095") {
		t.Fatal("expected localhost origin to pass without DNS trust")
	}
	if !isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://127.0.0.1:8095") {
		t.Fatal("expected literal IPv4 loopback origin to pass")
	}
	if !isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://[::1]:8095") {
		t.Fatal("expected literal IPv6 loopback origin to pass")
	}
	if isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://rebind.example:8095") {
		t.Fatal("expected DNS-rebinding hostname origin to be rejected")
	}
	if isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://127.0.0.1:5173") {
		t.Fatal("expected unauth loopback origin with different port to be rejected")
	}
}

func TestGPMAuthChallengeVerifyAndSessionStatus(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"

	challengeBody := `{"wallet_address":"cosmos1testwallet","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("challenge message missing: %v", payload)
	}
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1testwallet",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_kind":            "sign_arbitrary",
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signature_source":          "wallet_extension",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	sessionToken, _ := payload["session_token"].(string)
	if strings.TrimSpace(sessionToken) == "" {
		t.Fatalf("session_token missing: %v", payload)
	}

	sessionPayload, _ := payload["session"].(map[string]any)
	role, _ := sessionPayload["role"].(string)
	if role != "client" {
		t.Fatalf("session role=%q want=client", role)
	}

	statusBody := `{"session_token":"` + sessionToken + `"}`
	code, payload = callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
	if code != http.StatusOK {
		t.Fatalf("session status=%d body=%v", code, payload)
	}
	sessionPayload, _ = payload["session"].(map[string]any)
	statusRole, _ := sessionPayload["role"].(string)
	if statusRole != "client" {
		t.Fatalf("session status role=%q want=client", statusRole)
	}
	sessionReconciled, ok := payload["session_reconciled"].(bool)
	if !ok {
		t.Fatalf("session_reconciled missing in payload=%v", payload)
	}
	if sessionReconciled {
		t.Fatalf("session_reconciled=%v want=false payload=%v", sessionReconciled, payload)
	}

	code, payload = callJSONHandlerWithHeaders(
		t,
		svc.handleGPMSessionStatus,
		http.MethodPost,
		"/v1/gpm/session",
		`{"action":"status"}`,
		map[string]string{"X-GPM-Session-Token": sessionToken},
	)
	if code != http.StatusOK {
		t.Fatalf("session status with X-GPM-Session-Token=%d body=%v", code, payload)
	}
	sessionPayload, _ = payload["session"].(map[string]any)
	if statusRole, _ := sessionPayload["role"].(string); statusRole != "client" {
		t.Fatalf("session header status role=%q want=client", statusRole)
	}
}

func TestGPMSessionTokenHeaderSupportsPublicUserFlows(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-header-session", "cosmos1headersession", 2, true, true)

	headers := map[string]string{"X-GPM-Session-Token": token}
	for _, tc := range []struct {
		name      string
		handler   http.HandlerFunc
		method    string
		path      string
		body      string
		wantField string
	}{
		{
			name:      "contribution_status_get",
			handler:   svc.handleGPMContributionStatus,
			method:    http.MethodGet,
			path:      "/v1/gpm/contribution/status",
			wantField: "contribution_profile",
		},
		{
			name:      "contribution_status_post",
			handler:   svc.handleGPMContributionStatus,
			method:    http.MethodPost,
			path:      "/v1/gpm/contribution/status",
			body:      `{}`,
			wantField: "contribution_profile",
		},
		{
			name:      "rewards_current_week_get",
			handler:   svc.handleGPMRewardsCurrentWeek,
			method:    http.MethodGet,
			path:      "/v1/gpm/rewards/current-week",
			wantField: "reward",
		},
		{
			name:      "rewards_history_get",
			handler:   svc.handleGPMRewardsHistory,
			method:    http.MethodGet,
			path:      "/v1/gpm/rewards/history",
			wantField: "rewards",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandlerWithHeaders(t, tc.handler, tc.method, tc.path, tc.body, headers)
			if code != http.StatusOK {
				t.Fatalf("code=%d payload=%v", code, payload)
			}
			if _, ok := payload[tc.wantField]; !ok {
				t.Fatalf("missing %q payload=%v", tc.wantField, payload)
			}
		})
	}
}

func TestGPMContributionProductionRequiresTrustedEntitlementEvidence(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	token := seedGPMTestSession(t, svc, "gpm-prod-local-entitlements", "cosmos1prodlocalentitlements", 3, true, true)
	markGPMTestSessionEntitlementsLocal(t, svc, token)

	code, payload := callJSONHandler(t, svc.handleGPMContributionStatus, http.MethodGet, "/v1/gpm/contribution/status?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("status code=%d payload=%v", code, payload)
	}
	if canUse, _ := payload["can_use_micro_relays"].(bool); canUse {
		t.Fatalf("can_use_micro_relays=%v want=false payload=%v", canUse, payload)
	}
	if canEnable, _ := payload["can_enable_requested_role"].(bool); canEnable {
		t.Fatalf("can_enable_requested_role=%v want=false payload=%v", canEnable, payload)
	}
	if got, _ := payload["contribution_lock_reason"].(string); !strings.Contains(got, "trusted chain or signed entitlement evidence") {
		t.Fatalf("contribution_lock_reason=%q want trusted evidence guidance payload=%v", got, payload)
	}

	code, payload = callJSONHandler(t, svc.handleGPMContributionEnable, http.MethodPost, "/v1/gpm/contribution/enable", `{
		"session_token":"`+token+`",
		"role":"micro-relay"
	}`)
	if code != http.StatusForbidden {
		t.Fatalf("enable code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "trusted chain or signed entitlement evidence") {
		t.Fatalf("enable error=%q want trusted evidence guidance payload=%v", got, payload)
	}
}

func TestGPMContributionTierOneCannotUseOrProvideMicroRelay(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-tier1", "cosmos1tierone", 1, true, true)

	code, payload := callJSONHandler(t, svc.handleGPMContributionStatus, http.MethodGet, "/v1/gpm/contribution/status?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("status code=%d payload=%v", code, payload)
	}
	if canUse, _ := payload["can_use_micro_relays"].(bool); canUse {
		t.Fatalf("Tier 1 can_use_micro_relays=%v want=false payload=%v", canUse, payload)
	}
	if canEnable, _ := payload["can_enable_micro_relay"].(bool); canEnable {
		t.Fatalf("Tier 1 can_enable_micro_relay=%v want=false payload=%v", canEnable, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("enable code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "Tier 2 or Tier 3") {
		t.Fatalf("error=%q want Tier 2/3 payload=%v", errMsg, payload)
	}
}

func TestGPMContributionEntitlementsRemainSessionBoundAfterEnvChange(t *testing.T) {
	t.Setenv("GPM_STAKE_SATISFIED", "1")
	t.Setenv("GPM_PREPAID_BALANCE_SATISFIED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-session-bound-entitlements", "cosmos1sessionbound", 2, false, false)

	code, payload := callJSONHandler(t, svc.handleGPMContributionStatus, http.MethodPost, "/v1/gpm/contribution/status", `{"session_token":"`+token+`"}`)
	if code != http.StatusOK {
		t.Fatalf("status code=%d payload=%v", code, payload)
	}
	if stakeSatisfied, _ := payload["stake_satisfied"].(bool); stakeSatisfied {
		t.Fatalf("stake_satisfied=%v want=false from issued session payload=%v", stakeSatisfied, payload)
	}
	if prepaidSatisfied, _ := payload["prepaid_balance_satisfied"].(bool); prepaidSatisfied {
		t.Fatalf("prepaid_balance_satisfied=%v want=false from issued session payload=%v", prepaidSatisfied, payload)
	}
	if canUse, _ := payload["can_use_micro_relays"].(bool); canUse {
		t.Fatalf("can_use_micro_relays=%v want=false after env flip payload=%v", canUse, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("enable code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "stake requirement is not satisfied") {
		t.Fatalf("error=%q want session-bound stake guidance payload=%v", errMsg, payload)
	}
}

func TestGPMContributionMicroExitBetaRequiresExplicitPolicyOptIn(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-micro-exit-default-off", "cosmos1microexitdefaultoff", 3, true, true)

	code, payload := callJSONHandler(t, svc.handleGPMContributionStatus, http.MethodGet, "/v1/gpm/contribution/status?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("status code=%d payload=%v", code, payload)
	}
	if allowed, _ := payload["micro_exit_beta_allowed"].(bool); allowed {
		t.Fatalf("micro_exit_beta_allowed=%v want=false by default payload=%v", allowed, payload)
	}
	if canExit, _ := payload["can_enable_micro_exit"].(bool); canExit {
		t.Fatalf("can_enable_micro_exit=%v want=false by default payload=%v", canExit, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("enable code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "micro-exit beta is disabled by policy") {
		t.Fatalf("error=%q want disabled-by-policy guidance payload=%v", errMsg, payload)
	}
}

func TestGPMContributionMicroExitBetaMalformedPolicyFailsClosed(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "definitely")
	t.Setenv("TDPN_MICRO_EXIT_BETA_ALLOWED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-micro-exit-malformed", "cosmos1microexitmalformed", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("enable code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	status, _ := payload["status"].(map[string]any)
	if allowed, _ := status["micro_exit_beta_allowed"].(bool); allowed {
		t.Fatalf("micro_exit_beta_allowed=%v want=false when primary policy value is malformed payload=%v", allowed, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "micro-exit beta is disabled by policy") {
		t.Fatalf("error=%q want disabled-by-policy guidance payload=%v", errMsg, payload)
	}
}

func TestGPMContributionTierTwoEnablesMicroExitAndCurrentWeekReward(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	t.Setenv("GPM_CONTRIBUTION_TRAFFIC_PROOF_MODE", "trusted-counter-test")
	t.Setenv("GPM_AGENT_UPLINK_MBPS", "120")
	t.Setenv("GPM_AGENT_DOWNLINK_MBPS", "300")
	t.Setenv("GPM_AGENT_LATENCY_MS", "18")
	t.Setenv("GPM_AGENT_PACKET_LOSS_PCT", "0")
	t.Setenv("GPM_AGENT_MEMORY_GB", "16")
	t.Setenv("GPM_AGENT_RELIABILITY_PCT", "99")
	token := seedGPMTestSession(t, svc, "gpm-tier2", "cosmos1tiertwo", 2, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	if canExit, _ := payload["can_enable_micro_exit"].(bool); !canExit {
		t.Fatalf("can_enable_micro_exit=%v want=true payload=%v", canExit, payload)
	}
	profile, _ := payload["contribution_profile"].(map[string]any)
	if role, _ := profile["role"].(string); role != "micro-exit" {
		t.Fatalf("profile role=%q want=micro-exit payload=%v", role, payload)
	}
	if maxSessions := intFromAny(profile["max_forwarded_sessions"]); maxSessions <= 0 {
		t.Fatalf("max_forwarded_sessions=%d want>0 profile=%v", maxSessions, profile)
	}

	state, ok := svc.gpmState.getContribution("cosmos1tiertwo")
	if !ok {
		t.Fatal("expected contribution state to be persisted")
	}
	state.LastMeteredAt = time.Now().UTC().Add(-2 * time.Hour)
	svc.gpmState.upsertContribution(state)

	code, payload = callJSONHandler(t, svc.handleGPMRewardsCurrentWeek, http.MethodGet, "/v1/gpm/rewards/current-week?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("current-week code=%d payload=%v", code, payload)
	}
	reward, _ := payload["reward"].(map[string]any)
	if frequency, _ := payload["settlement_frequency"].(string); frequency != "weekly" {
		t.Fatalf("settlement_frequency=%q want=weekly payload=%v", frequency, payload)
	}
	if units := floatFromAny(reward["reward_units"]); units <= 0 {
		t.Fatalf("reward_units=%v want>0 reward=%v", reward["reward_units"], reward)
	}
}

func TestGPMContributionRewardReadsAcceptPostSessionTokenBody(t *testing.T) {
	t.Setenv("GPM_CONTRIBUTION_TRAFFIC_PROOF_MODE", "trusted-counter-test")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-post-body-reward", "cosmos1postbodyreward", 2, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}

	for _, tc := range []struct {
		name      string
		handler   http.HandlerFunc
		path      string
		wantField string
	}{
		{
			name:      "contribution_status",
			handler:   svc.handleGPMContributionStatus,
			path:      "/v1/gpm/contribution/status",
			wantField: "contribution_profile",
		},
		{
			name:      "rewards_current_week",
			handler:   svc.handleGPMRewardsCurrentWeek,
			path:      "/v1/gpm/rewards/current-week",
			wantField: "reward",
		},
		{
			name:      "rewards_history",
			handler:   svc.handleGPMRewardsHistory,
			path:      "/v1/gpm/rewards/history",
			wantField: "rewards",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.path, `{"session_token":"`+token+`"}`)
			if code != http.StatusOK {
				t.Fatalf("%s POST code=%d payload=%v", tc.name, code, payload)
			}
			if _, ok := payload[tc.wantField]; !ok {
				t.Fatalf("%s missing %q payload=%v", tc.name, tc.wantField, payload)
			}
		})
	}
}

func TestGPMContributionToggleRejectsUnboundWalletSession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		body    string
	}{
		{
			name:    "enable",
			handler: nil,
			body:    `{"session_token":"gpm-unbound-contribution","role":"micro-relay"}`,
		},
		{
			name:    "disable",
			handler: nil,
			body:    `{"session_token":"gpm-unbound-contribution"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.gpmState = newGPMRuntimeState()
			seedGPMUnboundTestSession(t, svc, "gpm-unbound-contribution", "cosmos1unboundcontribution")
			handler := svc.handleGPMContributionEnable
			if tc.name == "disable" {
				handler = svc.handleGPMContributionDisable
			}

			code, payload := callJSONHandler(t, handler, http.MethodPost, "/v1/gpm/contribution/"+tc.name, tc.body)
			if code != http.StatusForbidden {
				t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
			}
			if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound session") {
				t.Fatalf("error=%q want wallet-bound guidance payload=%v", got, payload)
			}
			if _, ok := svc.gpmState.getContribution("cosmos1unboundcontribution"); ok {
				t.Fatalf("unbound %s should not persist contribution state", tc.name)
			}
		})
	}
}

func TestGPMPublicSessionEndpointsRejectStaleWalletPolicy(t *testing.T) {
	tests := []struct {
		name    string
		handler func(*Service) http.HandlerFunc
		method  string
		path    string
		body    string
	}{
		{
			name:    "contribution_status_get",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMContributionStatus },
			method:  http.MethodGet,
			path:    "/v1/gpm/contribution/status?session_token=gpm-stale-wallet-policy",
		},
		{
			name:    "contribution_status_post",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMContributionStatus },
			method:  http.MethodPost,
			path:    "/v1/gpm/contribution/status",
			body:    `{"session_token":"gpm-stale-wallet-policy"}`,
		},
		{
			name:    "contribution_enable",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMContributionEnable },
			method:  http.MethodPost,
			path:    "/v1/gpm/contribution/enable",
			body:    `{"session_token":"gpm-stale-wallet-policy","role":"micro-relay"}`,
		},
		{
			name:    "contribution_disable",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMContributionDisable },
			method:  http.MethodPost,
			path:    "/v1/gpm/contribution/disable",
			body:    `{"session_token":"gpm-stale-wallet-policy"}`,
		},
		{
			name:    "settlement_reserve_funds",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMSettlementReserveFunds },
			method:  http.MethodPost,
			path:    "/v1/gpm/settlement/reserve-funds",
			body:    `{"session_token":"gpm-stale-wallet-policy","session_id":"vpn-session-stale-policy","amount_micros":200000,"currency":"TDPNC"}`,
		},
		{
			name:    "rewards_current_week_get",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMRewardsCurrentWeek },
			method:  http.MethodGet,
			path:    "/v1/gpm/rewards/current-week?session_token=gpm-stale-wallet-policy",
		},
		{
			name:    "rewards_current_week_post",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMRewardsCurrentWeek },
			method:  http.MethodPost,
			path:    "/v1/gpm/rewards/current-week",
			body:    `{"session_token":"gpm-stale-wallet-policy"}`,
		},
		{
			name:    "rewards_history_get",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMRewardsHistory },
			method:  http.MethodGet,
			path:    "/v1/gpm/rewards/history?session_token=gpm-stale-wallet-policy",
		},
		{
			name:    "rewards_history_post",
			handler: func(svc *Service) http.HandlerFunc { return svc.handleGPMRewardsHistory },
			method:  http.MethodPost,
			path:    "/v1/gpm/rewards/history",
			body:    `{"session_token":"gpm-stale-wallet-policy"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.gpmState = newGPMRuntimeState()
			seedGPMTestSession(t, svc, "gpm-stale-wallet-policy", "cosmos1stalepolicy", 2, true, true)
			svc.gpmAuthExpectedChainID = "gpm-testnet-1"

			code, payload := callJSONHandler(t, tc.handler(svc), tc.method, tc.path, tc.body)
			if code != http.StatusForbidden {
				t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
			}
			errMsg, _ := payload["error"].(string)
			if !strings.Contains(errMsg, "session no longer satisfies wallet auth policy") {
				t.Fatalf("error=%q want stale wallet policy guidance payload=%v", errMsg, payload)
			}
		})
	}
}

func TestGPMContributionCurrentWeekHoldsWithoutTrustedTrafficProof(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-traffic-proof-hold", "cosmos1trafficproofhold", 2, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	now := time.Now().UTC()
	state, ok := svc.gpmState.getContribution("cosmos1trafficproofhold")
	if !ok {
		t.Fatal("expected contribution state")
	}
	state.MeteredWeekStartUTC = gpmWeekStartUTC(now).Format(time.RFC3339)
	state.MeteredSeconds = 3600
	state.ValidBytes = 100_000_000
	state.PendingRewardUnits = gpmPendingRewardUnits(state)
	state.LastMeteredAt = now
	svc.gpmState.upsertContribution(state)

	code, payload = callJSONHandler(t, svc.handleGPMRewardsCurrentWeek, http.MethodGet, "/v1/gpm/rewards/current-week?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("current-week code=%d payload=%v", code, payload)
	}
	reward, _ := payload["reward"].(map[string]any)
	if status, _ := reward["status"].(string); status != "hold" {
		t.Fatalf("status=%q want=hold reward=%v payload=%v", status, reward, payload)
	}
	if proof, _ := reward["traffic_proof_status"].(string); proof != "missing" {
		t.Fatalf("traffic_proof_status=%q want=missing reward=%v", proof, reward)
	}
	if units := floatFromAny(reward["reward_units"]); units != 0 {
		t.Fatalf("reward_units=%v want=0 reward=%v", reward["reward_units"], reward)
	}
	if sources := fmt.Sprint(reward["hold_sources"]); !strings.Contains(sources, "pending_traffic_proof") {
		t.Fatalf("hold_sources=%v want pending_traffic_proof reward=%v", reward["hold_sources"], reward)
	}
}

func TestGPMContributionAdaptiveCapacityDemotesLowQualityDevices(t *testing.T) {
	t.Setenv("GPM_AGENT_UPLINK_MBPS", "3")
	t.Setenv("GPM_AGENT_DOWNLINK_MBPS", "12")
	t.Setenv("GPM_AGENT_LATENCY_MS", "140")
	t.Setenv("GPM_AGENT_PACKET_LOSS_PCT", "4")
	t.Setenv("GPM_AGENT_RELIABILITY_PCT", "55")
	low := gpmAdaptiveContributionProfile("micro-relay")
	if low.DemotionState != "disabled_capacity" && low.DemotionState != "disabled_health" {
		t.Fatalf("low-quality demotion_state=%q want disabled_capacity/disabled_health profile=%+v", low.DemotionState, low)
	}
	if strings.TrimSpace(low.LockReason) == "" {
		t.Fatalf("low-quality lock reason missing profile=%+v", low)
	}

	t.Setenv("GPM_AGENT_UPLINK_MBPS", "200")
	t.Setenv("GPM_AGENT_DOWNLINK_MBPS", "400")
	t.Setenv("GPM_AGENT_LATENCY_MS", "12")
	t.Setenv("GPM_AGENT_PACKET_LOSS_PCT", "0")
	t.Setenv("GPM_AGENT_RELIABILITY_PCT", "99")
	high := gpmAdaptiveContributionProfile("micro-relay")
	if high.MaxForwardedSessions <= low.MaxForwardedSessions {
		t.Fatalf("high max sessions=%d low=%d", high.MaxForwardedSessions, low.MaxForwardedSessions)
	}
	if high.MaxBandwidthMbps <= low.MaxBandwidthMbps {
		t.Fatalf("high bandwidth=%d low=%d", high.MaxBandwidthMbps, low.MaxBandwidthMbps)
	}
	if high.DemotionState != "none" {
		t.Fatalf("high-quality demotion_state=%q want=none profile=%+v", high.DemotionState, high)
	}
}

func TestGPMContributionWeeklyHistoryClosesPreviousEpochPendingAdminChain(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-history", "cosmos1history", 3, true, true)

	currentWeekStart := gpmWeekStartUTC(time.Now().UTC())
	previousWeekStart := currentWeekStart.AddDate(0, 0, -7)
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           "cosmos1history",
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              3,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		CapacityScore:           82,
		HealthScore:             91,
		MaxForwardedSessions:    12,
		MaxBandwidthMbps:        60,
		UptimeReliabilityPct:    98,
		DemotionState:           "none",
		MeteredWeekStartUTC:     previousWeekStart.Format(time.RFC3339),
		MeteredSeconds:          int64((36 * time.Hour).Seconds()),
		ValidBytes:              99_000_000,
		LastMeteredAt:           previousWeekStart.Add(36 * time.Hour),
		UpdatedAt:               previousWeekStart.Add(36 * time.Hour),
	})

	code, payload := callJSONHandler(t, svc.handleGPMRewardsHistory, http.MethodGet, "/v1/gpm/rewards/history?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("history code=%d payload=%v", code, payload)
	}
	if count := intFromAny(payload["count"]); count != 1 {
		t.Fatalf("history count=%d want=1 payload=%v", count, payload)
	}
	rewards, _ := payload["rewards"].([]any)
	if len(rewards) != 1 {
		t.Fatalf("rewards len=%d want=1 payload=%v", len(rewards), payload)
	}
	reward, _ := rewards[0].(map[string]any)
	if status, _ := reward["status"].(string); status != "hold" {
		t.Fatalf("reward status=%q want=hold reward=%v", status, reward)
	}
	if proof, _ := reward["traffic_proof_status"].(string); proof != "missing" {
		t.Fatalf("traffic_proof_status=%q want=missing reward=%v", proof, reward)
	}
	if sources := fmt.Sprint(reward["hold_sources"]); !strings.Contains(sources, "pending_traffic_proof") {
		t.Fatalf("hold_sources=%v want pending_traffic_proof reward=%v", reward["hold_sources"], reward)
	}
	if payoutAllowed, _ := reward["payout_allowed"].(bool); payoutAllowed {
		t.Fatalf("payout_allowed=%v want=false until admin+chain finalization reward=%v", payoutAllowed, reward)
	}
	if state, _ := reward["settlement_finalization_state"].(string); state != "pending_admin_chain_finalization" {
		t.Fatalf("settlement_finalization_state=%q reward=%v", state, reward)
	}
	if start, _ := reward["week_start_utc"].(string); start != previousWeekStart.Format(time.RFC3339) {
		t.Fatalf("week_start_utc=%q want=%q reward=%v", start, previousWeekStart.Format(time.RFC3339), reward)
	}
}

func TestGPMContributionWeeklyHistoryCanonicalizesStoredWeekStart(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-history-canonical", "cosmos1historycanon", 3, true, true)

	currentWeekStart := gpmWeekStartUTC(time.Now().UTC())
	previousWeekStart := currentWeekStart.AddDate(0, 0, -7)
	nonCanonicalStoredStart := previousWeekStart.AddDate(0, 0, 2).Add(6 * time.Hour)
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           "cosmos1historycanon",
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              3,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		CapacityScore:           82,
		HealthScore:             91,
		MaxForwardedSessions:    12,
		MaxBandwidthMbps:        60,
		UptimeReliabilityPct:    98,
		DemotionState:           "none",
		MeteredWeekStartUTC:     nonCanonicalStoredStart.Format(time.RFC3339),
		MeteredSeconds:          int64((18 * time.Hour).Seconds()),
		ValidBytes:              57_000_000,
		LastMeteredAt:           nonCanonicalStoredStart.Add(18 * time.Hour),
		UpdatedAt:               nonCanonicalStoredStart.Add(18 * time.Hour),
	})

	code, payload := callJSONHandler(t, svc.handleGPMRewardsHistory, http.MethodGet, "/v1/gpm/rewards/history?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("history code=%d payload=%v", code, payload)
	}
	rewards, _ := payload["rewards"].([]any)
	if len(rewards) != 1 {
		t.Fatalf("rewards len=%d want=1 payload=%v", len(rewards), payload)
	}
	reward, _ := rewards[0].(map[string]any)
	if start, _ := reward["week_start_utc"].(string); start != previousWeekStart.Format(time.RFC3339) {
		t.Fatalf("week_start_utc=%q want canonical %q reward=%v", start, previousWeekStart.Format(time.RFC3339), reward)
	}
	state, ok := svc.gpmState.getContribution("cosmos1historycanon")
	if !ok {
		t.Fatal("expected contribution state")
	}
	if state.MeteredWeekStartUTC != currentWeekStart.Format(time.RFC3339) {
		t.Fatalf("metered_week_start_utc=%q want current canonical %q state=%+v", state.MeteredWeekStartUTC, currentWeekStart.Format(time.RFC3339), state)
	}
}

func TestGPMContributionWeeklyHistoryRolloverIsIdempotentByEpoch(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-history-idempotent", "cosmos1historyidem", 3, true, true)

	currentWeekStart := gpmWeekStartUTC(time.Now().UTC())
	previousWeekStart := currentWeekStart.AddDate(0, 0, -7)
	existing := gpmWeeklyRewardSummary{
		WalletAddress:               "cosmos1historyidem",
		WeekStartUTC:                previousWeekStart.Format(time.RFC3339),
		WeekEndUTC:                  previousWeekStart.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Status:                      "hold",
		Role:                        "micro-relay",
		TrafficProofStatus:          "missing",
		SettlementFinalizationState: "pending_admin_chain_finalization",
		HoldSources:                 []string{"pending_traffic_proof"},
	}
	svc.gpmState.upsertRewardHistory("cosmos1historyidem", existing)
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           "cosmos1historyidem",
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              3,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		CapacityScore:           82,
		HealthScore:             91,
		MaxForwardedSessions:    12,
		MaxBandwidthMbps:        60,
		UptimeReliabilityPct:    98,
		DemotionState:           "none",
		MeteredWeekStartUTC:     previousWeekStart.Format(time.RFC3339),
		MeteredSeconds:          int64((12 * time.Hour).Seconds()),
		ValidBytes:              42_000_000,
		LastMeteredAt:           previousWeekStart.Add(12 * time.Hour),
		UpdatedAt:               previousWeekStart.Add(12 * time.Hour),
	})

	for i := 0; i < 2; i++ {
		code, payload := callJSONHandler(t, svc.handleGPMRewardsHistory, http.MethodGet, "/v1/gpm/rewards/history?session_token="+token, "")
		if code != http.StatusOK {
			t.Fatalf("history call %d code=%d payload=%v", i+1, code, payload)
		}
		if count := intFromAny(payload["count"]); count != 1 {
			t.Fatalf("history call %d count=%d want=1 payload=%v", i+1, count, payload)
		}
		rewards, _ := payload["rewards"].([]any)
		if len(rewards) != 1 {
			t.Fatalf("history call %d rewards len=%d want=1 payload=%v", i+1, len(rewards), payload)
		}
		reward, _ := rewards[0].(map[string]any)
		if start, _ := reward["week_start_utc"].(string); start != previousWeekStart.Format(time.RFC3339) {
			t.Fatalf("history call %d week_start_utc=%q want=%q reward=%v", i+1, start, previousWeekStart.Format(time.RFC3339), reward)
		}
	}
}

func TestGPMContributionAutoDemotionPersistsAndRewardsHold(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-auto-demote", "cosmos1autodemote", 2, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	state, ok := svc.gpmState.getContribution("cosmos1autodemote")
	if !ok {
		t.Fatal("expected contribution state")
	}
	now := time.Now().UTC()
	state.MeteredWeekStartUTC = gpmWeekStartUTC(now).Format(time.RFC3339)
	state.MeteredSeconds = 3600
	state.ValidBytes = 25_000_000
	state.PendingRewardUnits = gpmPendingRewardUnits(state)
	state.LastMeteredAt = now.Add(-1 * time.Hour)
	svc.gpmState.upsertContribution(state)

	seedGPMTestSession(t, svc, token, "cosmos1autodemote", 1, true, true)
	code, payload = callJSONHandler(t, svc.handleGPMRewardsCurrentWeek, http.MethodGet, "/v1/gpm/rewards/current-week?session_token="+token, "")
	if code != http.StatusOK {
		t.Fatalf("reward code=%d payload=%v", code, payload)
	}
	reward, _ := payload["reward"].(map[string]any)
	if status, _ := reward["status"].(string); status != "hold" {
		t.Fatalf("reward status=%q want=hold reward=%v payload=%v", status, reward, payload)
	}
	if units := floatFromAny(reward["reward_units"]); units != 0 {
		t.Fatalf("reward_units=%v want=0 reward=%v", reward["reward_units"], reward)
	}
	state, ok = svc.gpmState.getContribution("cosmos1autodemote")
	if !ok {
		t.Fatal("expected contribution state after demotion")
	}
	if state.Enabled {
		t.Fatalf("state.Enabled=true want=false state=%+v", state)
	}
	if state.DemotionState != "auto_demoted" {
		t.Fatalf("demotion_state=%q want=auto_demoted state=%+v", state.DemotionState, state)
	}
	if !strings.Contains(state.LockReason, "Tier 2 or Tier 3") {
		t.Fatalf("lock_reason=%q want Tier 2/3 state=%+v", state.LockReason, state)
	}
	if state.MeteredSeconds != 3600 {
		t.Fatalf("metered_seconds=%d want=3600; ineligible session must not accrue extra time state=%+v", state.MeteredSeconds, state)
	}
	if state.ValidBytes != 25_000_000 {
		t.Fatalf("valid_bytes=%d want=25000000; ineligible session must not accrue extra bytes state=%+v", state.ValidBytes, state)
	}
	if state.LastMeteredAt.Before(now) {
		t.Fatalf("last_metered_at=%s should move to demotion time after %s", state.LastMeteredAt, now)
	}

	seedGPMTestSession(t, svc, token, "cosmos1autodemote", 2, true, true)
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("reenable after demotion code=%d payload=%v", code, payload)
	}
	state, ok = svc.gpmState.getContribution("cosmos1autodemote")
	if !ok {
		t.Fatal("expected contribution state after reenable")
	}
	if state.MeteredSeconds != 0 {
		t.Fatalf("metered_seconds=%d want=0; auto-demoted metering must not carry into a later eligible opt-in state=%+v", state.MeteredSeconds, state)
	}
	if state.ValidBytes != 0 {
		t.Fatalf("valid_bytes=%d want=0; auto-demoted metering must not carry into a later eligible opt-in state=%+v", state.ValidBytes, state)
	}
}

func TestGPMContributionDisablePreservesLastContributionRoleForSettlement(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-disable-role", "cosmos1disablerole", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionDisable,
		http.MethodPost,
		"/v1/gpm/contribution/disable",
		`{"session_token":"`+token+`"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("disable code=%d payload=%v", code, payload)
	}
	state, ok := svc.gpmState.getContribution("cosmos1disablerole")
	if !ok {
		t.Fatal("expected contribution state")
	}
	if state.Enabled {
		t.Fatalf("state.Enabled=true want=false state=%+v", state)
	}
	if state.Role != "micro-exit" {
		t.Fatalf("state.Role=%q want=micro-exit state=%+v", state.Role, state)
	}
}

func TestGPMContributionReenablePreservesCurrentWeekMetering(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-reenable-metering", "cosmos1reenablemetering", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	now := time.Now().UTC()
	state, ok := svc.gpmState.getContribution("cosmos1reenablemetering")
	if !ok {
		t.Fatal("expected contribution state")
	}
	state.MeteredWeekStartUTC = gpmWeekStartUTC(now).Format(time.RFC3339)
	state.MeteredSeconds = 3600
	state.ValidBytes = 25_000_000
	state.PendingRewardUnits = gpmPendingRewardUnits(state)
	state.LastMeteredAt = now
	svc.gpmState.upsertContribution(state)

	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionDisable,
		http.MethodPost,
		"/v1/gpm/contribution/disable",
		`{"session_token":"`+token+`"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("disable code=%d payload=%v", code, payload)
	}
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("reenable code=%d payload=%v", code, payload)
	}
	state, ok = svc.gpmState.getContribution("cosmos1reenablemetering")
	if !ok {
		t.Fatal("expected contribution state after reenable")
	}
	if state.MeteredSeconds < 3600 {
		t.Fatalf("metered_seconds=%d want>=3600 state=%+v", state.MeteredSeconds, state)
	}
	if state.ValidBytes < 25_000_000 {
		t.Fatalf("valid_bytes=%d want>=25000000 state=%+v", state.ValidBytes, state)
	}
	if state.LastMeteredAt.Before(now) {
		t.Fatalf("last_metered_at=%s should restart at re-enable time after %s", state.LastMeteredAt, now)
	}
}

func TestGPMContributionRoleSwitchDoesNotRerateExistingMetering(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-role-switch-metering", "cosmos1roleswitchmetering", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable relay code=%d payload=%v", code, payload)
	}
	now := time.Now().UTC()
	state, ok := svc.gpmState.getContribution("cosmos1roleswitchmetering")
	if !ok {
		t.Fatal("expected contribution state")
	}
	state.MeteredWeekStartUTC = gpmWeekStartUTC(now).Format(time.RFC3339)
	state.MeteredSeconds = 7200
	state.ValidBytes = 50_000_000
	state.PendingRewardUnits = gpmPendingRewardUnits(state)
	state.LastMeteredAt = now
	svc.gpmState.upsertContribution(state)

	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionDisable,
		http.MethodPost,
		"/v1/gpm/contribution/disable",
		`{"session_token":"`+token+`"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("disable relay code=%d payload=%v", code, payload)
	}
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusConflict {
		t.Fatalf("enable exit code=%d payload=%v want conflict", code, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "next weekly epoch") {
		t.Fatalf("expected weekly epoch lock guidance, got payload=%v", payload)
	}
	state, ok = svc.gpmState.getContribution("cosmos1roleswitchmetering")
	if !ok {
		t.Fatal("expected contribution state after rejected role switch")
	}
	if state.Role != "micro-relay" {
		t.Fatalf("role=%q want=micro-relay after rejected role switch state=%+v", state.Role, state)
	}
	if state.MeteredSeconds != 7200 || state.ValidBytes != 50_000_000 {
		t.Fatalf("rejected role switch changed metering state=%+v", state)
	}
	history := svc.gpmState.rewardHistoryFor("cosmos1roleswitchmetering")
	if len(history) != 0 {
		t.Fatalf("history len=%d want=0 after rejected role switch history=%+v", len(history), history)
	}
}

func TestGPMContributionRoleSwitchWithoutCurrentWeekMeteringIsAllowed(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-role-switch-zero", "cosmos1roleswitchzero", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable relay code=%d payload=%v", code, payload)
	}
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable exit code=%d payload=%v", code, payload)
	}
	state, ok := svc.gpmState.getContribution("cosmos1roleswitchzero")
	if !ok {
		t.Fatal("expected contribution state after zero-metering role switch")
	}
	if state.Role != "micro-exit" {
		t.Fatalf("role=%q want=micro-exit state=%+v", state.Role, state)
	}
}

func TestGPMContributionFailedRoleEnableDoesNotDisableActiveRole(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "0")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-failed-role-enable", "cosmos1failedroleenable", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable relay code=%d payload=%v", code, payload)
	}
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+token+`","role":"micro-exit"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("enable locked exit code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	state, ok := svc.gpmState.getContribution("cosmos1failedroleenable")
	if !ok {
		t.Fatal("expected contribution state")
	}
	if !state.Enabled {
		t.Fatalf("active micro-relay was disabled by failed micro-exit request state=%+v", state)
	}
	if state.Role != "micro-relay" {
		t.Fatalf("role=%q want=micro-relay state=%+v", state.Role, state)
	}
	if state.DemotionState != "none" {
		t.Fatalf("demotion_state=%q want=none state=%+v", state.DemotionState, state)
	}
}

func TestGPMAdminContributionListRequiresAdminAndReturnsReviewSurface(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "1")
	t.Setenv("GPM_CONTRIBUTION_TRAFFIC_PROOF_MODE", "trusted-counter-test")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-review", "cosmos1adminreview")
	clientToken := seedGPMTestSession(t, svc, "gpm-client-review", "cosmos1clientreview", 3, true, true)
	microExitToken := seedGPMTestSession(t, svc, "gpm-client-review-exit", "cosmos1clientreviewexit", 3, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+clientToken+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	state, ok := svc.gpmState.getContribution("cosmos1clientreview")
	if !ok {
		t.Fatal("expected contribution state after enable")
	}
	state.LastMeteredAt = time.Now().UTC().Add(-90 * time.Minute)
	svc.gpmState.upsertContribution(state)
	code, payload = callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+microExitToken+`","role":"micro-exit"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable micro-exit code=%d payload=%v", code, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminContributionList,
		http.MethodPost,
		"/v1/gpm/admin/contributions/list",
		`{"session_token":"`+clientToken+`"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin list code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "admin session role") {
		t.Fatalf("non-admin error=%q payload=%v", errMsg, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminContributionList,
		http.MethodPost,
		"/v1/gpm/admin/contributions/list",
		`{"session_token":"`+adminToken+`","status":"enabled","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("admin list code=%d payload=%v", code, payload)
	}
	if surface, _ := payload["admin_api_surface"].(string); surface != "gpm_admin_console" {
		t.Fatalf("admin_api_surface=%q want=gpm_admin_console payload=%v", surface, payload)
	}
	if publicControls, _ := payload["public_app_admin_controls"].(bool); publicControls {
		t.Fatalf("public_app_admin_controls=%v want=false payload=%v", publicControls, payload)
	}
	if count := intFromAny(payload["count"]); count != 1 {
		t.Fatalf("count=%d want=1 payload=%v", count, payload)
	}
	items, _ := payload["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items len=%d want=1 payload=%v", len(items), payload)
	}
	item, _ := items[0].(map[string]any)
	if wallet, _ := item["wallet_address"].(string); wallet != "cosmos1clientreview" {
		t.Fatalf("wallet=%q want=cosmos1clientreview item=%v", wallet, item)
	}
	currentWeekReward, ok := item["current_week_reward"].(map[string]any)
	if !ok {
		t.Fatalf("current_week_reward missing item=%v", item)
	}
	if units := floatFromAny(currentWeekReward["reward_units"]); units <= 0 {
		t.Fatalf("admin list reward_units=%v want>0 after stale metering refresh reward=%v", currentWeekReward["reward_units"], currentWeekReward)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminContributionList,
		http.MethodPost,
		"/v1/gpm/admin/contributions/list",
		`{"session_token":"`+adminToken+`"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("admin all-role list code=%d payload=%v", code, payload)
	}
	if count := intFromAny(payload["count"]); count != 2 {
		t.Fatalf("all-role count=%d want=2 payload=%v", count, payload)
	}
}

func TestGPMSettlementReserveFundsBindsSubjectToWalletAndReplaysExactly(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-reserve-client", "cosmos1reserveclient", 2, true, true)

	body := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-1","subject_id":"cosmos1attacker","amount_micros":200000,"currency":"TDPNC"}`
	code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
	if code != http.StatusOK {
		t.Fatalf("reserve code=%d payload=%v", code, payload)
	}
	if publicControls, _ := payload["public_app_admin_controls"].(bool); publicControls {
		t.Fatalf("public_app_admin_controls=%v want=false payload=%v", publicControls, payload)
	}
	if replay, _ := payload["idempotent_replay"].(bool); replay {
		t.Fatalf("idempotent_replay=%v want=false on first reserve payload=%v", replay, payload)
	}
	reservation, _ := payload["reservation"].(map[string]any)
	if subject, _ := reservation["subject_id"].(string); subject != "cosmos1reserveclient" {
		t.Fatalf("reservation subject_id=%q want signed-in wallet; reservation=%v payload=%v", subject, reservation, payload)
	}
	if sessionID, _ := reservation["session_id"].(string); sessionID != "vpn-session-reserve-1" {
		t.Fatalf("reservation session_id=%q payload=%v", sessionID, payload)
	}
	if status, _ := reservation["status"].(string); status != string(settlement.OperationStatusConfirmed) {
		t.Fatalf("reservation status=%q want confirmed reservation=%v", status, reservation)
	}

	code, payload = callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
	if code != http.StatusOK {
		t.Fatalf("exact replay code=%d payload=%v", code, payload)
	}
	if replay, _ := payload["idempotent_replay"].(bool); !replay {
		t.Fatalf("idempotent_replay=%v want=true on exact reserve replay payload=%v", replay, payload)
	}

	amountDriftBody := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-arbitrary-amount","amount_micros":300000,"currency":"TDPNC"}`
	code, payload = callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", amountDriftBody)
	if code != http.StatusBadRequest {
		t.Fatalf("amount drift code=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "public VPN reservation amount") {
		t.Fatalf("amount drift error=%q payload=%v", errMsg, payload)
	}

	driftBody := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-1","reservation_id":"res-drift-reserve-1","amount_micros":200000,"currency":"TDPNC"}`
	code, payload = callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", driftBody)
	if code != http.StatusConflict {
		t.Fatalf("drift replay code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "fund reservation idempotency conflict") {
		t.Fatalf("drift error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMSettlementReserveFundsRequiresWalletBoundStakeAndPrepaid(t *testing.T) {
	t.Run("rejects unbound session", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.putSession(gpmSession{
			Token:                   "gpm-reserve-unbound",
			WalletAddress:           "cosmos1reserveunbound",
			Role:                    "client",
			StakeSatisfied:          true,
			PrepaidBalanceSatisfied: true,
			ExpiresAt:               time.Now().UTC().Add(time.Hour),
		})
		body := `{"session_token":"gpm-reserve-unbound","session_id":"vpn-session-reserve-unbound","amount_micros":200000}`
		code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
		if code != http.StatusForbidden {
			t.Fatalf("unbound code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "wallet-bound session") {
			t.Fatalf("unbound error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("rejects missing stake", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		token := seedGPMTestSession(t, svc, "gpm-reserve-no-stake", "cosmos1reservenostake", 2, false, true)
		body := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-no-stake","amount_micros":200000}`
		code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
		if code != http.StatusForbidden {
			t.Fatalf("no-stake code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "stake is required") {
			t.Fatalf("no-stake error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("rejects missing prepaid balance", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		token := seedGPMTestSession(t, svc, "gpm-reserve-no-prepaid", "cosmos1reservenoprepaid", 2, true, false)
		body := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-no-prepaid","amount_micros":200000}`
		code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
		if code != http.StatusForbidden {
			t.Fatalf("no-prepaid code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "prepaid balance is required") {
			t.Fatalf("no-prepaid error=%q payload=%v", errMsg, payload)
		}
	})
}

func TestGPMSettlementReserveFundsProductionRequiresTrustedEntitlementEvidence(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	token := seedGPMTestSession(t, svc, "gpm-reserve-prod-local", "cosmos1reserveprodlocal", 2, true, true)
	markGPMTestSessionEntitlementsLocal(t, svc, token)

	body := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-prod-local","amount_micros":200000,"currency":"TDPNC"}`
	code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
	if code != http.StatusForbidden {
		t.Fatalf("prod local evidence code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "trusted chain or signed entitlement evidence") {
		t.Fatalf("prod local evidence error=%q payload=%v", errMsg, payload)
	}
	if allowed, _ := payload["reservation_allowed"].(bool); allowed {
		t.Fatalf("reservation_allowed=%v want=false payload=%v", allowed, payload)
	}
}

func TestGPMSettlementReserveFundsProductionFailsClosedWithoutChainAdapter(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmSettlementChainRequired = true
	svc.gpmSettlementChainRequiredSource = "test-production"
	token := seedGPMTestSession(t, svc, "gpm-reserve-prod", "cosmos1reserveprod", 2, true, true)

	body := `{"session_token":"` + token + `","session_id":"vpn-session-reserve-prod","amount_micros":200000,"currency":"TDPNC"}`
	code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("prod code=%d want=%d payload=%v", code, http.StatusServiceUnavailable, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "chain-backed GPM settlement adapter is required") {
		t.Fatalf("prod error=%q payload=%v", errMsg, payload)
	}
	status, _ := payload["settlement_status"].(map[string]any)
	if mode, _ := status["gpm_settlement_mode"].(string); mode != "required_unconfigured" {
		t.Fatalf("settlement mode=%q want required_unconfigured status=%v payload=%v", mode, status, payload)
	}
	if allowed, _ := payload["reservation_allowed"].(bool); allowed {
		t.Fatalf("reservation_allowed=%v want=false payload=%v", allowed, payload)
	}
}

func TestResolveGPMSettlementWiringProductionRejectsSignedTxEnvelopeMode(t *testing.T) {
	t.Setenv("GPM_SETTLEMENT_BACKEND", "cosmos")
	t.Setenv("GPM_SETTLEMENT_COSMOS_ENDPOINT", "https://cosmos.globalprivatemesh.example")
	t.Setenv("GPM_SETTLEMENT_COSMOS_SUBMIT_MODE", settlement.CosmosSubmitModeSignedTx)
	t.Setenv("GPM_SETTLEMENT_COSMOS_SIGNED_TX_SIGNER", "cosmos1signer")
	t.Setenv("GPM_SETTLEMENT_COSMOS_SIGNED_TX_SECRET", "signed-tx-test-secret")

	wiring := resolveGPMSettlementWiring(true, "test-production", func(string, string) {})
	if wiring.chainBacked {
		t.Fatalf("chainBacked=%v want=false for experimental signed-tx production wiring", wiring.chainBacked)
	}
	if wiring.adapterConfigured {
		t.Fatalf("adapterConfigured=%v want=false for experimental signed-tx production wiring", wiring.adapterConfigured)
	}
	if !strings.Contains(wiring.adapterConfigError, "experimental signed-tx JSON envelope mode") {
		t.Fatalf("adapterConfigError=%q want experimental signed-tx production rejection", wiring.adapterConfigError)
	}
}

func TestResolveGPMSettlementWiringProductionRejectsTrustedBridgeFinality(t *testing.T) {
	t.Setenv("GPM_SETTLEMENT_BACKEND", "cosmos")
	t.Setenv("GPM_SETTLEMENT_COSMOS_ENDPOINT", "https://cosmos.globalprivatemesh.example")
	t.Setenv("GPM_SETTLEMENT_COSMOS_TRUSTED_BRIDGE_FINALITY", "1")

	wiring := resolveGPMSettlementWiring(true, "test-production", func(string, string) {})
	if wiring.chainBacked {
		t.Fatalf("chainBacked=%v want=false for trusted bridge finality production wiring", wiring.chainBacked)
	}
	if wiring.adapterConfigured {
		t.Fatalf("adapterConfigured=%v want=false for trusted bridge finality production wiring", wiring.adapterConfigured)
	}
	if !wiring.trustedBridgeFinality {
		t.Fatalf("trustedBridgeFinality=%v want=true for telemetry and diagnostics", wiring.trustedBridgeFinality)
	}
	if !strings.Contains(wiring.adapterConfigError, "trusted HTTP bridge finality") {
		t.Fatalf("adapterConfigError=%q want trusted bridge finality production rejection", wiring.adapterConfigError)
	}
}

func TestResolveGPMSettlementWiringForwardsScopedBridgeTokens(t *testing.T) {
	t.Setenv("GPM_SETTLEMENT_BACKEND", "cosmos")
	t.Setenv("GPM_SETTLEMENT_COSMOS_ENDPOINT", "https://cosmos.globalprivatemesh.example")
	t.Setenv("GPM_SETTLEMENT_COSMOS_API_KEY", "bridge-token")
	t.Setenv("GPM_SETTLEMENT_COSMOS_TRUSTED_BRIDGE_FINALITY", "1")
	t.Setenv("GPM_SETTLEMENT_COSMOS_REWARD_PROOF_AUTH_TOKEN", "proof-token")
	t.Setenv("GPM_SETTLEMENT_COSMOS_FINALITY_AUTH_TOKEN", "finality-token")

	wiring := resolveGPMSettlementWiring(false, "test-compat", func(string, string) {})
	if !wiring.chainBacked || !wiring.adapterConfigured {
		t.Fatalf("expected scoped-token Cosmos wiring to configure adapter, chainBacked=%v adapterConfigured=%v error=%q", wiring.chainBacked, wiring.adapterConfigured, wiring.adapterConfigError)
	}
	if !wiring.trustedBridgeFinality {
		t.Fatalf("trustedBridgeFinality=%v want=true", wiring.trustedBridgeFinality)
	}
	if wiring.adapterConfigError != "" {
		t.Fatalf("adapterConfigError=%q want empty", wiring.adapterConfigError)
	}
}

func TestGPMSettlementReserveFundsBlockchainFinalityRequiresConfirmedReservation(t *testing.T) {
	tests := []struct {
		name         string
		localStatus  settlement.OperationStatus
		chainStatus  settlement.OperationStatus
		chainFound   bool
		wantCode     int
		wantAllowed  bool
		wantState    string
		wantStatus   settlement.OperationStatus
		wantSource   string
		wantErrorSub string
	}{
		{
			name:        "confirmed_allows",
			chainStatus: settlement.OperationStatusConfirmed,
			chainFound:  true,
			wantCode:    http.StatusOK,
			wantAllowed: true,
			wantState:   "chain_confirmed",
			wantStatus:  settlement.OperationStatusConfirmed,
			wantSource:  "chain_status_query",
		},
		{
			name:         "pending_submission_holds",
			chainStatus:  settlement.OperationStatusPending,
			chainFound:   true,
			wantCode:     http.StatusAccepted,
			wantAllowed:  false,
			wantState:    "pending_chain_submission",
			wantStatus:   settlement.OperationStatusPending,
			wantSource:   "chain_status_query",
			wantErrorSub: "pending chain submission",
		},
		{
			name:         "pending_confirmation_holds",
			chainStatus:  settlement.OperationStatusSubmitted,
			chainFound:   true,
			wantCode:     http.StatusAccepted,
			wantAllowed:  false,
			wantState:    "pending_chain_confirmation",
			wantStatus:   settlement.OperationStatusSubmitted,
			wantSource:   "chain_status_query",
			wantErrorSub: "pending chain confirmation",
		},
		{
			name:         "query_miss_uses_local_pending_submission",
			localStatus:  settlement.OperationStatusPending,
			chainFound:   false,
			wantCode:     http.StatusAccepted,
			wantAllowed:  false,
			wantState:    "pending_chain_submission",
			wantStatus:   settlement.OperationStatusPending,
			wantSource:   "settlement_service_pending_chain_status_query_miss",
			wantErrorSub: "pending chain submission",
		},
		{
			name:         "query_miss_uses_local_pending_confirmation",
			localStatus:  settlement.OperationStatusSubmitted,
			chainFound:   false,
			wantCode:     http.StatusAccepted,
			wantAllowed:  false,
			wantState:    "pending_chain_confirmation",
			wantStatus:   settlement.OperationStatusSubmitted,
			wantSource:   "settlement_service_pending_chain_status_query_miss",
			wantErrorSub: "pending chain confirmation",
		},
		{
			name:         "query_miss_with_unknown_local_status_fails_closed",
			localStatus:  settlement.OperationStatus("mystery"),
			chainFound:   false,
			wantCode:     http.StatusServiceUnavailable,
			wantAllowed:  false,
			wantState:    "unknown_chain_status",
			wantSource:   "chain_status_query",
			wantErrorSub: "chain status is unknown",
		},
		{
			name:         "rejected_fails_closed",
			chainStatus:  settlement.OperationStatusFailed,
			chainFound:   true,
			wantCode:     http.StatusConflict,
			wantAllowed:  false,
			wantState:    "chain_rejected",
			wantStatus:   settlement.OperationStatusFailed,
			wantSource:   "chain_status_query",
			wantErrorSub: "rejected by chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.gpmState = newGPMRuntimeState()
			svc.gpmSettlementChainRequired = true
			svc.gpmSettlementChainRequiredSource = "test-production"
			svc.gpmSettlementChainBacked = true
			svc.gpmSettlementBackend = "cosmos"
			localStatus := tc.localStatus
			if localStatus == "" {
				localStatus = settlement.OperationStatusSubmitted
			}
			svc.gpmSettlement = &gpmReserveFundsFinalityService{
				returnedStatus: localStatus,
				chainStatus:    tc.chainStatus,
				chainFound:     tc.chainFound,
			}
			wallet := "cosmos1reservefinality" + strings.ReplaceAll(tc.name, "_", "")
			token := seedGPMTestSession(t, svc, "gpm-reserve-finality-"+tc.name, wallet, 2, true, true)

			body := `{"session_token":"` + token + `","session_id":"vpn-session-` + tc.name + `","amount_micros":200000,"currency":"TDPNC"}`
			code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
			if code != tc.wantCode {
				t.Fatalf("code=%d want=%d payload=%v", code, tc.wantCode, payload)
			}
			if allowed, _ := payload["reservation_allowed"].(bool); allowed != tc.wantAllowed {
				t.Fatalf("reservation_allowed=%v want=%v payload=%v", allowed, tc.wantAllowed, payload)
			}
			if state, _ := payload["reservation_finalization_state"].(string); state != tc.wantState {
				t.Fatalf("reservation_finalization_state=%q want=%q payload=%v", state, tc.wantState, payload)
			}
			if source, _ := payload["reservation_status_source"].(string); source != tc.wantSource {
				t.Fatalf("reservation_status_source=%q want %q payload=%v", source, tc.wantSource, payload)
			}
			if status, _ := payload["reservation_chain_status"].(string); status != string(tc.wantStatus) {
				t.Fatalf("reservation_chain_status=%q want=%q payload=%v", status, tc.wantStatus, payload)
			}
			if tc.wantAllowed {
				if ok, _ := payload["ok"].(bool); !ok {
					t.Fatalf("ok=%v want=true payload=%v", ok, payload)
				}
				return
			}
			if ok, _ := payload["ok"].(bool); ok {
				t.Fatalf("ok=%v want=false for held/fail-closed reservation payload=%v", ok, payload)
			}
			if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, tc.wantErrorSub) {
				t.Fatalf("error=%q want substring %q payload=%v", errMsg, tc.wantErrorSub, payload)
			}
		})
	}
}

func TestGPMSettlementReserveFundsBlockchainFinalityUsesWrappedMemoryAdapterStatus(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmSettlementChainRequired = true
	svc.gpmSettlementChainRequiredSource = "test-production"
	svc.gpmSettlementChainBacked = true
	svc.gpmSettlementBackend = "cosmos"
	adapter := &gpmReserveFundsChainStatusAdapter{
		status: settlement.OperationStatusConfirmed,
		found:  true,
	}
	svc.gpmSettlement = settlement.NewMemoryService(
		settlement.WithBlockchainMode(true),
		settlement.WithChainAdapter(adapter),
	)
	token := seedGPMTestSession(t, svc, "gpm-reserve-wrapped-finality", "cosmos1reservewrappedfinality", 2, true, true)

	body := `{"session_token":"` + token + `","session_id":"vpn-session-wrapped-finality","amount_micros":200000,"currency":"TDPNC"}`
	code, payload := callJSONHandler(t, svc.handleGPMSettlementReserveFunds, http.MethodPost, "/v1/gpm/settlement/reserve-funds", body)
	if code != http.StatusOK {
		t.Fatalf("code=%d want=%d payload=%v", code, http.StatusOK, payload)
	}
	if allowed, _ := payload["reservation_allowed"].(bool); !allowed {
		t.Fatalf("reservation_allowed=%v want=true payload=%v", allowed, payload)
	}
	if state, _ := payload["reservation_finalization_state"].(string); state != "chain_confirmed" {
		t.Fatalf("reservation_finalization_state=%q want chain_confirmed payload=%v", state, payload)
	}
	if source, _ := payload["reservation_status_source"].(string); source != "chain_status_query" {
		t.Fatalf("reservation_status_source=%q want chain_status_query payload=%v", source, payload)
	}
	if status, _ := payload["reservation_chain_status"].(string); status != string(settlement.OperationStatusConfirmed) {
		t.Fatalf("reservation_chain_status=%q want confirmed payload=%v", status, payload)
	}
	if len(adapter.submittedReservations) != 1 {
		t.Fatalf("submittedReservations=%d want=1 payload=%v", len(adapter.submittedReservations), payload)
	}
	if len(adapter.reservationStatusCalls) != 1 || adapter.reservationStatusCalls[0] != adapter.submittedReservations[0].ReservationID {
		t.Fatalf("reservationStatusCalls=%v submitted=%v", adapter.reservationStatusCalls, adapter.submittedReservations)
	}
}

func TestGPMAdminRewardReviewRequiresAdminAndSurfacesSlashEvidenceIntegration(t *testing.T) {
	t.Setenv("GPM_MICRO_EXIT_BETA_ALLOWED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-reward", "cosmos1adminreward")
	clientToken := seedGPMTestSession(t, svc, "gpm-client-reward", "cosmos1clientreward", 2, true, true)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+clientToken+`","role":"micro-exit"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminRewardReview,
		http.MethodPost,
		"/v1/gpm/admin/rewards/review",
		`{"session_token":"`+clientToken+`","wallet_address":"cosmos1clientreward"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin review code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminRewardReview,
		http.MethodPost,
		"/v1/gpm/admin/rewards/review",
		`{"session_token":"`+adminToken+`","wallet_address":"cosmos1clientreward"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("admin review code=%d payload=%v", code, payload)
	}
	if state, _ := payload["settlement_finalization_state"].(string); state != "pending_chain_bound_admin_console" {
		t.Fatalf("settlement_finalization_state=%q payload=%v", state, payload)
	}
	if integration, _ := payload["slashing_hold_integration"].(string); integration != "local_settlement_slash_evidence" {
		t.Fatalf("slashing_hold_integration=%q payload=%v", integration, payload)
	}
	if _, ok := payload["current_week_reward"].(map[string]any); !ok {
		t.Fatalf("current_week_reward missing payload=%v", payload)
	}
}

func TestGPMAdminRewardReviewAndFinalizeHoldChainSlashEvidence(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-slash-hold", "cosmos1adminslashhold")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1slashhold"
	summary := gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-exit",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               90,
		HealthScore:                 85,
		RewardUnits:                 3.75,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	}
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-exit",
		RequestedRole:           "micro-exit",
		ClientTier:              3,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, summary)
	if _, err := svc.gpmSettlementService().SubmitSlashEvidence(context.Background(), settlement.SlashEvidence{
		EvidenceID:    "slash-gpm-weekly-review-1",
		SubjectID:     wallet,
		SessionID:     gpmWeeklyRewardSessionID(summary),
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   "sha256:" + strings.Repeat("a", 64),
		SlashMicros:   125,
		Currency:      "TDPNC",
		ObservedAt:    weekStart.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardReview, http.MethodPost, "/v1/gpm/admin/rewards/review", body)
	if code != http.StatusOK {
		t.Fatalf("admin review code=%d payload=%v", code, payload)
	}
	if integration, _ := payload["slashing_hold_integration"].(string); integration != "local_settlement_slash_evidence" {
		t.Fatalf("slashing_hold_integration=%q payload=%v", integration, payload)
	}
	if count := intFromAny(payload["chain_slashing_hold_count"]); count != 1 {
		t.Fatalf("chain_slashing_hold_count=%d want=1 payload=%v", count, payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status != "hold" {
		t.Fatalf("selected reward status=%q want=hold reward=%v payload=%v", status, selectedReward, payload)
	}
	if sources := fmt.Sprint(selectedReward["hold_sources"]); !strings.Contains(sources, "slashing_evidence") {
		t.Fatalf("hold_sources=%v want slashing_evidence reward=%v", selectedReward["hold_sources"], selectedReward)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardHold, http.MethodPost, "/v1/gpm/admin/rewards/hold", `{"session_token":"`+adminToken+`","wallet_address":"`+wallet+`","week_start_utc":"`+weekStart.Format(time.RFC3339)+`","action":"release"}`)
	if code != http.StatusOK {
		t.Fatalf("release code=%d payload=%v", code, payload)
	}
	if count := intFromAny(payload["chain_slashing_hold_count"]); count != 1 {
		t.Fatalf("chain_slashing_hold_count after manual release=%d want=1 payload=%v", count, payload)
	}
	selectedReward, _ = payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status != "hold" {
		t.Fatalf("selected reward status after manual release=%q want=hold reward=%v payload=%v", status, selectedReward, payload)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if count := intFromAny(payload["chain_slashing_hold_count"]); count != 1 {
		t.Fatalf("finalize chain_slashing_hold_count=%d want=1 payload=%v", count, payload)
	}
}

func TestGPMAdminRewardFinalizeHoldsZeroTimestampSessionSlashEvidence(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adapter := &gpmRewardFinalizeConfirmationAdapter{}
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithBlockchainMode(true), settlement.WithChainAdapter(adapter))
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-zero-slash-hold", "cosmos1adminzeroslashhold")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1zeroslashhold"
	summary := gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "signed_traffic_proof",
		TrafficProofRef:             "sha256:" + strings.Repeat("e", 64),
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	}
	adapter.slashEvidence = []settlement.SlashEvidence{{
		EvidenceID:    "slash-gpm-zero-session-1",
		SubjectID:     wallet,
		SessionID:     gpmWeeklyRewardSessionID(summary),
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   "sha256:" + strings.Repeat("f", 64),
	}}
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, summary)

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if count := intFromAny(payload["chain_slashing_hold_count"]); count != 1 {
		t.Fatalf("chain_slashing_hold_count=%d want=1 payload=%v", count, payload)
	}
	if len(adapter.slashListCalls) == 0 || !adapter.slashListCalls[0].IncludeZeroObserved {
		t.Fatalf("expected session slash lookup to include zero observed records, calls=%+v", adapter.slashListCalls)
	}
}

func TestGPMAdminRewardFinalizeUsesClosedTrustedWeekDespiteCurrentStakeEligibilityLoss(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-stake-lock", "cosmos1adminstakefinalize")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1stakelockfinalize"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 false,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          false,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              3600,
		ValidBytes:                  100_000_000,
		RewardUnits:                 1.25,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "signed_traffic_proof",
		TrafficProofRef:             "sha256:" + strings.Repeat("b", 64),
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("finalize code=%d want=%d payload=%v", code, http.StatusOK, payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status != "finalized_chain_confirmed" {
		t.Fatalf("selected reward status=%q want=finalized_chain_confirmed reward=%v payload=%v", status, selectedReward, payload)
	}
	if units := floatFromAny(selectedReward["reward_units"]); units != 1.25 {
		t.Fatalf("reward_units=%v want preserved closed-week reward reward=%v payload=%v", units, selectedReward, payload)
	}
	if allowed, _ := selectedReward["payout_allowed"].(bool); !allowed {
		t.Fatalf("payout_allowed=%v want true reward=%v payload=%v", allowed, selectedReward, payload)
	}
}

func TestGPMAdminRewardReviewHonorsSelectedWeek(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-selected-week", "cosmos1adminselectedweek")
	wallet := "cosmos1selectedweek"
	now := time.Now().UTC()
	currentWeek := gpmWeekStartUTC(now)
	selectedWeek := currentWeek.AddDate(0, 0, -7)
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     currentWeek.Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                selectedWeek.Format(time.RFC3339),
		WeekEndUTC:                  selectedWeek.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	code, payload := callJSONHandler(
		t,
		svc.handleGPMAdminRewardReview,
		http.MethodPost,
		"/v1/gpm/admin/rewards/review",
		`{"session_token":"`+adminToken+`","wallet_address":"`+wallet+`","week_start_utc":"`+selectedWeek.Format(time.RFC3339)+`"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("admin review code=%d payload=%v", code, payload)
	}
	if got, _ := payload["selected_week_start_utc"].(string); got != selectedWeek.Format(time.RFC3339) {
		t.Fatalf("selected_week_start_utc=%q want=%q payload=%v", got, selectedWeek.Format(time.RFC3339), payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if got, _ := selectedReward["week_start_utc"].(string); got != selectedWeek.Format(time.RFC3339) {
		t.Fatalf("selected reward week_start_utc=%q want=%q reward=%v", got, selectedWeek.Format(time.RFC3339), selectedReward)
	}
	if status, _ := selectedReward["status"].(string); status != "week_closed_pending_admin_chain" {
		t.Fatalf("selected reward status=%q reward=%v", status, selectedReward)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminRewardHold,
		http.MethodPost,
		"/v1/gpm/admin/rewards/hold",
		`{"session_token":"`+adminToken+`","wallet_address":"`+wallet+`","week_start_utc":"`+selectedWeek.Format(time.RFC3339)+`","action":"hold","source":"manual_review","reason":"historical week review"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("historical hold code=%d payload=%v", code, payload)
	}
	selectedReward, _ = payload["selected_week_reward"].(map[string]any)
	if got, _ := selectedReward["week_start_utc"].(string); got != selectedWeek.Format(time.RFC3339) {
		t.Fatalf("held selected reward week_start_utc=%q want=%q reward=%v", got, selectedWeek.Format(time.RFC3339), selectedReward)
	}
	if status, _ := selectedReward["status"].(string); status != "hold" {
		t.Fatalf("held selected reward status=%q want=hold reward=%v", status, selectedReward)
	}
}

func TestGPMAdminRewardHoldRequiresAdminAndBlocksReward(t *testing.T) {
	t.Setenv("GPM_CONTRIBUTION_TRAFFIC_PROOF_MODE", "trusted-counter-test")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-hold", "cosmos1adminhold")
	clientToken := seedGPMTestSession(t, svc, "gpm-client-hold", "cosmos1clienthold", 2, true, true)
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now)

	code, payload := callJSONHandler(
		t,
		svc.handleGPMContributionEnable,
		http.MethodPost,
		"/v1/gpm/contribution/enable",
		`{"session_token":"`+clientToken+`","role":"micro-relay"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("enable code=%d payload=%v", code, payload)
	}
	state, ok := svc.gpmState.getContribution("cosmos1clienthold")
	if !ok {
		t.Fatal("expected contribution state")
	}
	state.MeteredWeekStartUTC = weekStart.Format(time.RFC3339)
	state.MeteredSeconds = 3600
	state.ValidBytes = 120_000_000
	state.PendingRewardUnits = gpmPendingRewardUnits(state)
	state.LastMeteredAt = now
	svc.gpmState.upsertContribution(state)

	holdBody := `{"session_token":"` + clientToken + `","wallet_address":"cosmos1clienthold","week_start_utc":"` + weekStart.Format(time.RFC3339) + `","action":"hold","source":"slashing_evidence","reason":"operator slash evidence pending"}`
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardHold, http.MethodPost, "/v1/gpm/admin/rewards/hold", holdBody)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin hold code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}

	holdBody = `{"session_token":"` + adminToken + `","wallet_address":"cosmos1clienthold","week_start_utc":"` + weekStart.Format(time.RFC3339) + `","action":"hold","source":"slashing_evidence","reason":"operator slash evidence pending"}`
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardHold, http.MethodPost, "/v1/gpm/admin/rewards/hold", holdBody)
	if code != http.StatusBadRequest {
		t.Fatalf("reserved-source hold code=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "reserved for chain-derived evidence") {
		t.Fatalf("reserved-source error=%q payload=%v", errMsg, payload)
	}

	holdBody = `{"session_token":"` + adminToken + `","wallet_address":"cosmos1clienthold","week_start_utc":"` + weekStart.Format(time.RFC3339) + `","action":"hold","source":"manual_admin_review","reason":"operator slash evidence pending"}`
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardHold, http.MethodPost, "/v1/gpm/admin/rewards/hold", holdBody)
	if code != http.StatusOK {
		t.Fatalf("admin hold code=%d payload=%v", code, payload)
	}
	if count := intFromAny(payload["active_hold_count"]); count != 1 {
		t.Fatalf("active_hold_count=%d want=1 payload=%v", count, payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status != "hold" {
		t.Fatalf("selected reward status=%q want=hold reward=%v payload=%v", status, selectedReward, payload)
	}
	if units := floatFromAny(selectedReward["reward_units"]); units != 0 {
		t.Fatalf("held reward_units=%v want=0 reward=%v", selectedReward["reward_units"], selectedReward)
	}
	if sources := fmt.Sprint(selectedReward["hold_sources"]); !strings.Contains(sources, "admin_reward_hold") {
		t.Fatalf("hold_sources=%v want admin_reward_hold reward=%v", selectedReward["hold_sources"], selectedReward)
	}

	code, payload = callJSONHandler(t, svc.handleGPMRewardsCurrentWeek, http.MethodGet, "/v1/gpm/rewards/current-week?session_token="+clientToken, "")
	if code != http.StatusOK {
		t.Fatalf("current-week code=%d payload=%v", code, payload)
	}
	reward, _ := payload["reward"].(map[string]any)
	if status, _ := reward["status"].(string); status != "hold" {
		t.Fatalf("current-week status=%q want=hold reward=%v payload=%v", status, reward, payload)
	}

	releaseBody := `{"session_token":"` + adminToken + `","wallet_address":"cosmos1clienthold","week_start_utc":"` + weekStart.Format(time.RFC3339) + `","action":"release"}`
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardHold, http.MethodPost, "/v1/gpm/admin/rewards/hold", releaseBody)
	if code != http.StatusOK {
		t.Fatalf("admin release code=%d payload=%v", code, payload)
	}
	if count := intFromAny(payload["active_hold_count"]); count != 0 {
		t.Fatalf("active_hold_count=%d want=0 payload=%v", count, payload)
	}
	selectedReward, _ = payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status == "hold" {
		t.Fatalf("selected reward status=%q want non-hold after release reward=%v payload=%v", status, selectedReward, payload)
	}
	if units := floatFromAny(selectedReward["reward_units"]); units <= 0 {
		t.Fatalf("released reward_units=%v want>0 reward=%v", selectedReward["reward_units"], selectedReward)
	}
}

func TestGPMAdminRewardFinalizeIssuesSettlementForClosedTrustedWeek(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize", "cosmos1adminfinalize")
	clientToken := seedGPMTestSession(t, svc, "gpm-client-finalize", "cosmos1finalize", 2, true, true)
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           "cosmos1finalize",
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory("cosmos1finalize", gpmWeeklyRewardSummary{
		WalletAddress:               "cosmos1finalize",
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               80,
		HealthScore:                 90,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	code, payload := callJSONHandler(
		t,
		svc.handleGPMAdminRewardFinalize,
		http.MethodPost,
		"/v1/gpm/admin/rewards/finalize",
		`{"session_token":"`+clientToken+`","wallet_address":"cosmos1finalize","week_start_utc":"`+weekStart.Format(time.RFC3339)+`"}`,
	)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin finalize code=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminRewardFinalize,
		http.MethodPost,
		"/v1/gpm/admin/rewards/finalize",
		`{"session_token":"`+adminToken+`","wallet_address":"cosmos1finalize"}`,
	)
	if code != http.StatusBadRequest {
		t.Fatalf("missing week_start_utc finalize code=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "week_start_utc is required") {
		t.Fatalf("missing week_start_utc error=%q payload=%v", errMsg, payload)
	}

	currentState, ok := svc.gpmState.getContribution("cosmos1finalize")
	if !ok {
		t.Fatal("expected current contribution state")
	}
	currentState.StakeSatisfied = false
	currentState.PrepaidBalanceSatisfied = false
	currentState.LockReason = "current week eligibility changed after closed-week reward was recorded"
	svc.gpmState.upsertContribution(currentState)

	code, payload = callJSONHandler(
		t,
		svc.handleGPMAdminRewardFinalize,
		http.MethodPost,
		"/v1/gpm/admin/rewards/finalize",
		`{"session_token":"`+adminToken+`","wallet_address":"cosmos1finalize","week_start_utc":"`+weekStart.Format(time.RFC3339)+`"}`,
	)
	if code != http.StatusOK {
		t.Fatalf("admin finalize code=%d payload=%v", code, payload)
	}
	if allowed, _ := payload["payout_allowed"].(bool); !allowed {
		t.Fatalf("payout_allowed=%v want=true payload=%v", allowed, payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status != "finalized_chain_confirmed" {
		t.Fatalf("status=%q want finalized_chain_confirmed reward=%v payload=%v", status, selectedReward, payload)
	}
	if state, _ := selectedReward["settlement_finalization_state"].(string); state != "chain_confirmed" {
		t.Fatalf("settlement_finalization_state=%q want chain_confirmed reward=%v", state, selectedReward)
	}
	if issueID, _ := selectedReward["reward_issue_id"].(string); issueID == "" {
		t.Fatalf("reward_issue_id missing reward=%v", selectedReward)
	}
	history := svc.gpmState.rewardHistoryFor("cosmos1finalize")
	if len(history) != 1 {
		t.Fatalf("history len=%d want=1 history=%v", len(history), history)
	}
	if history[0].Status != "finalized_chain_confirmed" || !history[0].PayoutAllowed {
		t.Fatalf("history[0]=%+v want finalized confirmed payout", history[0])
	}
}

func TestGPMAdminRewardFinalizeIdempotentReplayReconcilesChainStatus(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adapter := &gpmRewardFinalizeConfirmationAdapter{}
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(adapter))
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-reconcile", "cosmos1adminfinalizereconcile")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizereconcile"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               80,
		HealthScore:                 90,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("initial finalize code=%d payload=%v", code, payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if chainStatus, _ := selectedReward["settlement_chain_status"].(string); chainStatus != string(settlement.OperationStatusSubmitted) {
		t.Fatalf("initial settlement_chain_status=%q want submitted reward=%v payload=%v", chainStatus, selectedReward, payload)
	}
	if allowed, _ := payload["payout_allowed"].(bool); allowed {
		t.Fatalf("initial payout_allowed=%v want=false until chain confirmation payload=%v", allowed, payload)
	}

	history := svc.gpmState.rewardHistoryFor(wallet)
	if len(history) != 1 {
		t.Fatalf("history len after initial finalize=%d want=1 history=%v", len(history), history)
	}
	history[0].GeneratedAtUTC = now.Add(2 * time.Hour).Format(time.RFC3339)
	svc.gpmState.upsertRewardHistory(wallet, history[0])

	adapter.confirmRewards = true
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("idempotent finalize code=%d payload=%v", code, payload)
	}
	if replay, _ := payload["idempotent_replay"].(bool); !replay {
		t.Fatalf("idempotent_replay=%v want=true payload=%v", replay, payload)
	}
	if allowed, _ := payload["payout_allowed"].(bool); !allowed {
		t.Fatalf("payout_allowed=%v want=true after reconcile payload=%v", allowed, payload)
	}
	selectedReward, _ = payload["selected_week_reward"].(map[string]any)
	if chainStatus, _ := selectedReward["settlement_chain_status"].(string); chainStatus != string(settlement.OperationStatusConfirmed) {
		t.Fatalf("settlement_chain_status=%q want confirmed reward=%v payload=%v", chainStatus, selectedReward, payload)
	}
	if status, _ := selectedReward["status"].(string); status != "finalized_chain_confirmed" {
		t.Fatalf("status=%q want finalized_chain_confirmed reward=%v payload=%v", status, selectedReward, payload)
	}
	history = svc.gpmState.rewardHistoryFor(wallet)
	if len(history) != 1 {
		t.Fatalf("history len=%d want=1 history=%v", len(history), history)
	}
	if history[0].SettlementChainStatus != string(settlement.OperationStatusConfirmed) || !history[0].PayoutAllowed {
		t.Fatalf("history[0]=%+v want confirmed payout after idempotent reconcile", history[0])
	}
	if adapter.rewardSubmitCalls != 1 {
		t.Fatalf("rewardSubmitCalls=%d want=1; idempotent replay should load existing issue without resubmitting", adapter.rewardSubmitCalls)
	}
	if _, err := svc.gpmSettlementService().SubmitSlashEvidence(context.Background(), settlement.SlashEvidence{
		EvidenceID:    "slash-gpm-finalize-replay-1",
		SubjectID:     wallet,
		SessionID:     gpmWeeklyRewardSessionID(history[0]),
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   "sha256:" + strings.Repeat("b", 64),
		SlashMicros:   250,
		Currency:      "TDPNC",
		ObservedAt:    weekStart.Add(3 * time.Hour),
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence after finalize: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("idempotent finalize with slash hold code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if count := intFromAny(payload["chain_slashing_hold_count"]); count != 1 {
		t.Fatalf("chain_slashing_hold_count=%d want=1 payload=%v", count, payload)
	}
}

func TestGPMAdminRewardFinalizeReplayUsesPersistedSettlementIssuedAt(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adapter := &gpmRewardFinalizeConfirmationAdapter{}
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(adapter))
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-issued-at", "cosmos1adminfinalizeissuedat")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	generatedAt := weekStart.Add(12 * time.Hour).UTC()
	wallet := "cosmos1finalizeissuedat"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               80,
		HealthScore:                 90,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              generatedAt.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("initial finalize code=%d payload=%v", code, payload)
	}
	history := svc.gpmState.rewardHistoryFor(wallet)
	if len(history) != 1 {
		t.Fatalf("history len after initial finalize=%d want=1 history=%v", len(history), history)
	}
	if history[0].SettlementIssuedAtUTC != generatedAt.Format(time.RFC3339) {
		t.Fatalf("settlement_issued_at_utc=%q want original generated_at %q history=%+v", history[0].SettlementIssuedAtUTC, generatedAt.Format(time.RFC3339), history[0])
	}
	if history[0].FinalizedAtUTC == generatedAt.Format(time.RFC3339) {
		t.Fatalf("test fixture expected finalized_at to differ from original issued-at material history=%+v", history[0])
	}

	adapter.confirmRewards = true
	if _, err := svc.gpmSettlementService().Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile after chain confirmation: %v", err)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("retry finalize code=%d payload=%v", code, payload)
	}
	if replay, _ := payload["idempotent_replay"].(bool); !replay {
		t.Fatalf("idempotent_replay=%v want=true payload=%v", replay, payload)
	}
	if allowed, _ := payload["payout_allowed"].(bool); !allowed {
		t.Fatalf("payout_allowed=%v want=true after confirmed replay payload=%v", allowed, payload)
	}
	history = svc.gpmState.rewardHistoryFor(wallet)
	if len(history) != 1 {
		t.Fatalf("history len after retry=%d want=1 history=%v", len(history), history)
	}
	if history[0].SettlementIssuedAtUTC != generatedAt.Format(time.RFC3339) {
		t.Fatalf("settlement_issued_at_utc after retry=%q want %q history=%+v", history[0].SettlementIssuedAtUTC, generatedAt.Format(time.RFC3339), history[0])
	}
	if history[0].SettlementChainStatus != string(settlement.OperationStatusConfirmed) || !history[0].PayoutAllowed {
		t.Fatalf("history[0]=%+v want confirmed payout after issued-at stable replay", history[0])
	}
	if adapter.rewardSubmitCalls != 1 {
		t.Fatalf("rewardSubmitCalls=%d want=1; retry should not resubmit changed material", adapter.rewardSubmitCalls)
	}
}

func TestGPMAdminRewardFinalizeReplayRequiresTrustedTrafficProof(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(&gpmRewardFinalizeConfirmationAdapter{}))
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-replay-untrusted", "cosmos1adminfinalizeuntrusted")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizeuntrusted"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               80,
		HealthScore:                 90,
		RewardUnits:                 2.5,
		Status:                      "finalized_chain_submitted",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_chain_confirmation",
		TrafficProofStatus:          "untrusted",
		MeteringSource:              "untrusted_counter",
		RewardIssueID:               "gpm-weekly-reward-existing-untrusted",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("replay finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "trusted traffic proof is required") {
		t.Fatalf("error=%q want trusted proof requirement payload=%v", errMsg, payload)
	}
	if _, ok := payload["idempotent_replay"]; ok {
		t.Fatalf("idempotent_replay should not be reached for untrusted proof payload=%v", payload)
	}
}

func TestGPMAdminRewardFinalizeReplayRejectsMaterialDrift(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(&gpmRewardFinalizeConfirmationAdapter{}))
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-drift", "cosmos1adminfinalizedrift")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizedrift"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               80,
		HealthScore:                 90,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("initial finalize code=%d payload=%v", code, payload)
	}

	history := svc.gpmState.rewardHistoryFor(wallet)
	if len(history) != 1 {
		t.Fatalf("history len=%d want=1 history=%v", len(history), history)
	}
	history[0].RewardUnits = 3.5
	history[0].GeneratedAtUTC = now.Add(2 * time.Hour).Format(time.RFC3339)
	svc.gpmState.upsertRewardHistory(wallet, history[0])

	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("material-drift finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "settlement reward replay failed") || !strings.Contains(errMsg, "idempotency conflict") {
		t.Fatalf("error=%q want replay idempotency conflict payload=%v", errMsg, payload)
	}
	if replay, _ := payload["idempotent_replay"].(bool); replay {
		t.Fatalf("idempotent_replay=%v want=false on material drift payload=%v", replay, payload)
	}
}

func TestGPMAdminRewardFinalizeBlocksUnsafeEpochs(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-block", "cosmos1adminfinalizeblock")
	now := time.Now().UTC()
	currentWeek := gpmWeekStartUTC(now)
	previousWeek := currentWeek.AddDate(0, 0, -7)
	wallet := "cosmos1finalizeblock"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     currentWeek.Format(time.RFC3339),
		MeteredSeconds:          600,
		ValidBytes:              12_000_000,
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                previousWeek.Format(time.RFC3339),
		WeekEndUTC:                  previousWeek.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              3600,
		ValidBytes:                  100_000_000,
		RewardUnits:                 1.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	currentBody := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + currentWeek.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", currentBody)
	if code != http.StatusConflict {
		t.Fatalf("current-week finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "only closed weekly reward epochs") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}

	svc.gpmState.upsertRewardHold(gpmRewardHold{
		HoldID:        "hold-finalize-block",
		WalletAddress: wallet,
		WeekStartUTC:  previousWeek.Format(time.RFC3339),
		Source:        "slashing_evidence",
		Reason:        "slash evidence pending",
		Status:        "active",
		CreatedBy:     "cosmos1adminfinalizeblock",
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	heldBody := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + previousWeek.Format(time.RFC3339) + `"}`
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", heldBody)
	if code != http.StatusConflict {
		t.Fatalf("held finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "active holds") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMAdminRewardFinalizeProductionRejectsTrustedCounterWithoutObjectiveProofRef(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	adapter := &gpmRewardFinalizeConfirmationAdapter{}
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(adapter))
	svc.gpmSettlementChainBacked = true
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-prod-proof", "cosmos1adminfinalizeprodproof")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizeprodproof"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "trusted_counter",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("admin finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "objective signed or chain-queryable traffic proof evidence") {
		t.Fatalf("error=%q want objective proof-ref requirement payload=%v", errMsg, payload)
	}
	if adapter.rewardSubmitCalls != 0 {
		t.Fatalf("rewardSubmitCalls=%d want=0; production proof guard must run before reward submission", adapter.rewardSubmitCalls)
	}
}

func TestGPMAdminRewardFinalizeProductionRejectsSettlementReferenceWithoutTrafficProofRef(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	adapter := &gpmRewardFinalizeConfirmationAdapter{}
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(adapter))
	svc.gpmSettlementChainBacked = true
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-settlement-ref-proof", "cosmos1adminfinalizesettlementrefproof")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizesettlementrefproof"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "chain_traffic_proof",
		SettlementReferenceID:       "settlement-ref-only",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("admin finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "objective signed or chain-queryable traffic proof evidence") {
		t.Fatalf("error=%q want objective proof-ref requirement payload=%v", errMsg, payload)
	}
	if adapter.rewardSubmitCalls != 0 {
		t.Fatalf("rewardSubmitCalls=%d want=0; settlement references must not bypass production proof guard", adapter.rewardSubmitCalls)
	}
}

func TestGPMAdminRewardFinalizeProductionRejectsFormatOnlyTrafficProofRef(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	adapter := &gpmRewardFinalizeConfirmationAdapter{}
	svc.gpmSettlement = settlement.NewMemoryService(settlement.WithChainAdapter(adapter))
	svc.gpmSettlementChainBacked = true
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-format-proof", "cosmos1adminfinalizeformatproof")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizeformatproof"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "signed_traffic_proof",
		TrafficProofRef:             "sha256:" + strings.Repeat("c", 64),
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("admin finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "objective signed or chain-queryable traffic proof evidence") {
		t.Fatalf("error=%q want stronger proof-ref requirement payload=%v", errMsg, payload)
	}
	if adapter.rewardSubmitCalls != 0 {
		t.Fatalf("rewardSubmitCalls=%d want=0; production proof guard must run before reward submission", adapter.rewardSubmitCalls)
	}
}

func TestGPMAdminRewardFinalizeProductionFailsClosedWithoutChainAdapter(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-pending", "cosmos1adminfinalizepending")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizepending"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-exit",
		RequestedRole:           "micro-exit",
		ClientTier:              3,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-exit",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 4.25,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "signed_traffic_proof",
		TrafficProofRef:             "sha256:" + strings.Repeat("c", 64),
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("admin finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "active holds") {
		t.Fatalf("error=%q want active hold requirement payload=%v", errMsg, payload)
	}
	if holdErr, _ := payload["slashing_hold_error"].(string); !strings.Contains(holdErr, "chain adapter not configured") {
		t.Fatalf("slashing_hold_error=%q want chain adapter requirement payload=%v", holdErr, payload)
	}
	if count := intFromAny(payload["active_hold_count"]); count != 1 {
		t.Fatalf("active_hold_count=%d want=1 payload=%v", count, payload)
	}
	history := svc.gpmState.rewardHistoryFor(wallet)
	if len(history) != 1 {
		t.Fatalf("history len=%d want=1 history=%v", len(history), history)
	}
	if history[0].RewardIssueID != "" || history[0].Status != "week_closed_pending_admin_chain" {
		t.Fatalf("history[0]=%+v want unfinalized after fail-closed response", history[0])
	}
}

func TestGPMAdminRewardFinalizeProductionRequiresSlashEvidenceLister(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	svc.gpmSettlement = gpmNoSlashEvidenceListService{
		Service: settlement.NewMemoryService(settlement.WithBlockchainMode(true)),
	}
	svc.gpmSettlementChainBacked = true
	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-no-slash-lister", "cosmos1adminfinalizenoslash")
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizenoslash"
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		RewardUnits:                 4.25,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "signed_metered_counter",
		TrafficProofRef:             "obj://gpm-weekly-proof/finalize-no-slash-lister",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	})

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload := callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusConflict {
		t.Fatalf("admin finalize code=%d want=%d payload=%v", code, http.StatusConflict, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "active holds") {
		t.Fatalf("error=%q want active hold requirement payload=%v", errMsg, payload)
	}
	if integration, _ := payload["slashing_hold_integration"].(string); integration != "local_settlement_slash_evidence_error" {
		t.Fatalf("slashing_hold_integration=%q want local_settlement_slash_evidence_error payload=%v", integration, payload)
	}
	if holdErr, _ := payload["slashing_hold_error"].(string); !strings.Contains(holdErr, "chain slash evidence lister") {
		t.Fatalf("slashing_hold_error=%q want missing lister production guard payload=%v", holdErr, payload)
	}
	if count := intFromAny(payload["active_hold_count"]); count != 1 {
		t.Fatalf("active_hold_count=%d want=1 payload=%v", count, payload)
	}
}

func TestGPMSettlementCosmosEnvWiringProductionFinalizesViaChainAdapter(t *testing.T) {
	const apiKey = "settlement-api-token"
	const expectedAuth = "Bearer " + apiKey
	postCh := make(chan string, 1)
	queryCh := make(chan string, 1)
	now := time.Now().UTC()
	weekStart := gpmWeekStartUTC(now).AddDate(0, 0, -7)
	wallet := "cosmos1finalizecosmos"
	rewardID := "gpm-weekly-reward-" + wallet + "-" + weekStart.Format("20060102")
	sessionID := "gpm-weekly-session-" + wallet + "-" + weekStart.Format("20060102")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != expectedAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/x/vpnrewards/issues":
			select {
			case postCh <- r.URL.Path:
			default:
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/x/vpnrewards/proofs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proof": map[string]any{
					"verified":            true,
					"verifier_id":         "test-cosmos-proof-registry",
					"verified_at_utc":     now.Format(time.RFC3339),
					"traffic_proof_ref":   "obj://traffic-proof/gpm-finalize-cosmos",
					"trust_contract":      string(settlement.RewardProofTrustContractObjectiveTrafficV1),
					"reward_id":           rewardID,
					"provider_subject_id": wallet,
					"session_id":          sessionID,
					"payout_period_start": weekStart.Format(time.RFC3339),
					"payout_period_end":   weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
					"reward_micros":       int64(2_500_000),
					"currency":            "TDPNC",
					"issued_at":           now.Format(time.RFC3339),
				},
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/x/vpnrewards/distributions/dist:gpm-weekly-reward-"):
			select {
			case queryCh <- r.URL.Path:
			default:
			}
			payoutRef, _ := json.Marshal(map[string]any{
				"RewardID":          rewardID,
				"TrafficProofRef":   "obj://traffic-proof/gpm-finalize-cosmos",
				"PayoutPeriodStart": weekStart.Format(time.RFC3339),
				"PayoutPeriodEnd":   weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"distribution": map[string]any{
					"DistributionID":    "dist:" + rewardID,
					"AccrualID":         rewardID,
					"PayoutRef":         string(payoutRef),
					"DistributedAtUnix": now.Unix(),
					"Status":            string(settlement.OperationStatusConfirmed),
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/x/vpnrewards/accruals/"+rewardID:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accrual": map[string]any{
					"AccrualID":       rewardID,
					"SessionID":       sessionID,
					"ProviderID":      wallet,
					"AssetDenom":      "TDPNC",
					"Amount":          int64(2_500_000),
					"AccruedAtUnix":   now.Unix(),
					"PayoutStartUnix": weekStart.Unix(),
					"PayoutEndUnix":   weekStart.AddDate(0, 0, 7).Unix(),
					"OperationState":  string(settlement.OperationStatusConfirmed),
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/x/vpnslashing/evidence":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "evidence": []any{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "1")
	t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", "")
	t.Setenv("GPM_PRODUCTION_MODE", "1")
	t.Setenv("TDPN_PRODUCTION_MODE", "")
	t.Setenv("GPM_SETTLEMENT_BACKEND", "")
	t.Setenv("TDPN_SETTLEMENT_BACKEND", "")
	t.Setenv("GPM_SETTLEMENT_COSMOS_ENDPOINT", srv.URL)
	t.Setenv("TDPN_SETTLEMENT_COSMOS_ENDPOINT", "")
	t.Setenv("GPM_SETTLEMENT_COSMOS_API_KEY", apiKey)
	t.Setenv("GPM_SETTLEMENT_COSMOS_REWARD_PROOF_VERIFIER_ID", "test-cosmos-proof-registry")
	t.Setenv("TDPN_SETTLEMENT_COSMOS_API_KEY", "")
	t.Setenv("GPM_SETTLEMENT_COSMOS_QUEUE_SIZE", "8")
	t.Setenv("GPM_SETTLEMENT_COSMOS_MAX_RETRIES", "1")
	t.Setenv("GPM_SETTLEMENT_COSMOS_BASE_BACKOFF_MS", "1")
	t.Setenv("GPM_SETTLEMENT_COSMOS_HTTP_TIMEOUT_SEC", "2")
	t.Setenv("GPM_STATE_STORE_PATH", filepath.Join(tmpDir, "gpm_state.json"))
	t.Setenv("GPM_AUDIT_LOG_PATH", filepath.Join(tmpDir, "gpm_audit.jsonl"))

	svc := New()
	if svc.gpmSettlementClose != nil {
		t.Cleanup(svc.gpmSettlementClose)
	}
	svc.gpmState = newGPMRuntimeState()
	if !svc.gpmSettlementChainBacked {
		t.Fatalf("gpmSettlementChainBacked=%v want=true config_error=%q", svc.gpmSettlementChainBacked, svc.gpmSettlementAdapterConfigError)
	}
	if svc.gpmSettlementBackend != "cosmos" {
		t.Fatalf("gpmSettlementBackend=%q want=cosmos", svc.gpmSettlementBackend)
	}

	code, payload := callJSONHandler(t, svc.handleConfig, http.MethodGet, "/v1/config", "")
	if code != http.StatusOK {
		t.Fatalf("config status=%d payload=%v", code, payload)
	}
	configMap, _ := payload["config"].(map[string]any)
	if configMap == nil {
		t.Fatalf("config missing payload=%v", payload)
	}
	if got, _ := configMap["gpm_settlement_mode"].(string); got != "chain_backed" {
		t.Fatalf("gpm_settlement_mode=%q want chain_backed config=%v", got, configMap)
	}
	if got, _ := configMap["gpm_settlement_backend"].(string); got != "cosmos" {
		t.Fatalf("gpm_settlement_backend=%q want cosmos config=%v", got, configMap)
	}
	if got, _ := configMap["gpm_settlement_backend_source"].(string); got != "GPM_SETTLEMENT_COSMOS_ENDPOINT" {
		t.Fatalf("gpm_settlement_backend_source=%q want endpoint source config=%v", got, configMap)
	}
	if got, _ := configMap["gpm_settlement_chain_required"].(bool); !got {
		t.Fatalf("gpm_settlement_chain_required=%v want=true config=%v", got, configMap)
	}
	if got, _ := configMap["gpm_settlement_chain_backed"].(bool); !got {
		t.Fatalf("gpm_settlement_chain_backed=%v want=true config=%v", got, configMap)
	}
	if got, _ := configMap["gpm_settlement_adapter_configured"].(bool); !got {
		t.Fatalf("gpm_settlement_adapter_configured=%v want=true config=%v", got, configMap)
	}
	if got, _ := configMap["gpm_settlement_adapter_config_error"].(string); got != "" {
		t.Fatalf("gpm_settlement_adapter_config_error=%q want empty config=%v", got, configMap)
	}
	if _, exists := configMap["gpm_settlement_cosmos_api_key"]; exists {
		t.Fatalf("gpm_settlement_cosmos_api_key must not be exposed config=%v", configMap)
	}

	adminToken := seedGPMAdminTestSession(t, svc, "gpm-admin-finalize-cosmos", "cosmos1adminfinalizecosmos")
	summary := gpmWeeklyRewardSummary{
		WalletAddress:               wallet,
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        "micro-relay",
		MeteredSeconds:              7200,
		ValidBytes:                  500_000_000,
		CapacityScore:               80,
		HealthScore:                 90,
		RewardUnits:                 2.5,
		Status:                      "week_closed_pending_admin_chain",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		TrafficProofStatus:          "trusted",
		MeteringSource:              "signed_traffic_proof",
		TrafficProofRef:             "obj://traffic-proof/gpm-finalize-cosmos",
		GeneratedAtUTC:              now.Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	}
	svc.gpmState.upsertContribution(gpmContributionState{
		WalletAddress:           wallet,
		Enabled:                 true,
		Role:                    "micro-relay",
		RequestedRole:           "micro-relay",
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		MeteredWeekStartUTC:     gpmWeekStartUTC(now).Format(time.RFC3339),
		LastMeteredAt:           now,
	})
	svc.gpmState.appendRewardHistory(wallet, summary)

	body := `{"session_token":"` + adminToken + `","wallet_address":"` + wallet + `","week_start_utc":"` + weekStart.Format(time.RFC3339) + `"}`
	code, payload = callJSONHandler(t, svc.handleGPMAdminRewardFinalize, http.MethodPost, "/v1/gpm/admin/rewards/finalize", body)
	if code != http.StatusOK {
		t.Fatalf("admin finalize code=%d payload=%v", code, payload)
	}
	if allowed, _ := payload["payout_allowed"].(bool); !allowed {
		t.Fatalf("payout_allowed=%v want=true payload=%v", allowed, payload)
	}
	selectedReward, _ := payload["selected_week_reward"].(map[string]any)
	if status, _ := selectedReward["status"].(string); status != "finalized_chain_confirmed" {
		t.Fatalf("status=%q want finalized_chain_confirmed reward=%v payload=%v", status, selectedReward, payload)
	}
	settlementStatus, _ := payload["settlement_status"].(map[string]any)
	if settlementStatus == nil {
		t.Fatalf("settlement_status missing payload=%v", payload)
	}
	if got, _ := settlementStatus["gpm_settlement_mode"].(string); got != "chain_backed" {
		t.Fatalf("gpm_settlement_mode=%q want chain_backed status=%v payload=%v", got, settlementStatus, payload)
	}

	select {
	case <-queryCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for reward confirmation query")
	}
	select {
	case <-postCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for reward issue submission")
	}
}

func TestGPMAuthChallengeFailsClosedWhenChallengeStateSaturated(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	for i := 0; i < gpmChallengeMaxEntries; i++ {
		ok := svc.gpmState.putChallenge(gpmWalletChallenge{
			ChallengeID:    fmt.Sprintf("gpm-chal-seed-%d", i),
			WalletAddress:  fmt.Sprintf("cosmos1challengefill%d", i),
			WalletProvider: "keplr",
			Message:        "seed-challenge",
			ExpiresAt:      now.Add(gpmChallengeTTL),
		}, now)
		if !ok {
			t.Fatalf("seed challenge insert failed at i=%d", i)
		}
	}

	code, payload := callJSONHandler(
		t,
		svc.handleGPMAuthChallenge,
		http.MethodPost,
		"/v1/gpm/auth/challenge",
		`{"wallet_address":"cosmos1challengefill","wallet_provider":"keplr"}`,
	)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "temporarily saturated") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyRejectsSignatureWithWhitespaceControlCharacters(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"

	challengeBody := `{"wallet_address":"cosmos1sigguard","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}

	verifyBody := `{"wallet_address":"cosmos1sigguard","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed proofvalue"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "whitespace/control") {
		t.Fatalf("error=%q want contains whitespace/control payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyUsesCustomSignatureVerifier(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	expectedSignature := ""

	verifierCalls := 0
	svc.gpmAuthSignatureVerifier = func(challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string) error {
		verifierCalls++
		if strings.TrimSpace(challenge.ChallengeID) == "" {
			return errors.New("challenge id missing")
		}
		if walletAddress != "cosmos1customverifier" {
			return fmt.Errorf("wallet_address=%q", walletAddress)
		}
		if walletProvider != "keplr" {
			return fmt.Errorf("wallet_provider=%q", walletProvider)
		}
		if signature != expectedSignature {
			return fmt.Errorf("signature=%q", signature)
		}
		return nil
	}

	challengeBody := `{"wallet_address":"cosmos1customverifier","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("challenge message missing: %v", payload)
	}
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	expectedSignature = signature

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1customverifier",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if verifierCalls != 1 {
		t.Fatalf("verifierCalls=%d want=1", verifierCalls)
	}
	sessionToken, _ := payload["session_token"].(string)
	if strings.TrimSpace(sessionToken) == "" {
		t.Fatalf("session_token missing: %v", payload)
	}
	if verified, _ := payload["wallet_binding_verified"].(bool); verified {
		t.Fatalf("wallet_binding_verified=%v want=false for metadata-blind custom verifier payload=%v", verified, payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if verified, _ := sessionPayload["wallet_binding_verified"].(bool); verified {
		t.Fatalf("session.wallet_binding_verified=%v want=false for metadata-blind custom verifier payload=%v", verified, payload)
	}
}

func TestGPMAuthVerifyMintsAdminOnlyForVerifiedAllowlistedWallet(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	adminWallet := deterministicSecp256k1WalletAddress(t, "cosmos")
	svc.gpmAdminWalletAllowlist = normalizeGPMAdminWalletAllowlist(adminWallet + ", cosmos1otheradmin")
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature("admin-bound-signature", "bad-signature", 12)
	expectedSignature := ""

	svc.gpmAuthSignatureVerifier = func(challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string) error {
		if walletAddress != adminWallet {
			return fmt.Errorf("wallet_address=%q", walletAddress)
		}
		if walletProvider != "keplr" {
			return fmt.Errorf("wallet_provider=%q", walletProvider)
		}
		if signature != expectedSignature {
			return fmt.Errorf("signature=%q", signature)
		}
		if strings.TrimSpace(challenge.Message) == "" {
			return errors.New("challenge message missing")
		}
		return nil
	}

	challengeBody := `{"wallet_address":"` + adminWallet + `","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	challengeMessage, _ := payload["message"].(string)
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	expectedSignature = signature
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature(signature, "bad-signature", 12)

	verifyRequest := map[string]any{
		"wallet_address":            adminWallet,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "admin" {
		t.Fatalf("role=%q want=admin payload=%v", role, payload)
	}
	if verified, _ := sessionPayload["wallet_binding_verified"].(bool); !verified {
		t.Fatalf("wallet_binding_verified=%v want=true payload=%v", verified, payload)
	}
	token, _ := payload["session_token"].(string)
	session, ok := svc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatalf("admin session not stored for token %q", token)
	}
	if session.Role != "admin" || !session.WalletBindingVerified {
		t.Fatalf("session=%+v want wallet-bound admin", session)
	}
}

func TestGPMAuthVerifyDoesNotMintAdminForAllowlistWithoutCommandVerifier(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAdminWalletAllowlist = normalizeGPMAdminWalletAllowlist("cosmos1adminnocmd")
	expectedSignature := ""

	svc.gpmAuthSignatureVerifier = func(challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string) error {
		if walletAddress != "cosmos1adminnocmd" {
			return fmt.Errorf("wallet_address=%q", walletAddress)
		}
		if walletProvider != "keplr" {
			return fmt.Errorf("wallet_provider=%q", walletProvider)
		}
		if signature != expectedSignature {
			return fmt.Errorf("signature=%q", signature)
		}
		if strings.TrimSpace(challenge.Message) == "" {
			return errors.New("challenge message missing")
		}
		return nil
	}

	challengeBody := `{"wallet_address":"cosmos1adminnocmd","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	challengeMessage, _ := payload["message"].(string)
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	expectedSignature = signature
	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1adminnocmd",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "client" {
		t.Fatalf("role=%q want=client when command verifier absent payload=%v", role, payload)
	}
	if verified, _ := sessionPayload["wallet_binding_verified"].(bool); verified {
		t.Fatalf("wallet_binding_verified=%v want=false when command verifier absent payload=%v", verified, payload)
	}
}

func TestGPMAuthVerifyDefaultVerifierCannotMintAllowlistedAdmin(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAdminWalletAllowlist = normalizeGPMAdminWalletAllowlist("cosmos1admindefault")

	challengeBody := `{"wallet_address":"cosmos1admindefault","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	challengeMessage, _ := payload["message"].(string)
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1admindefault",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "client" {
		t.Fatalf("role=%q want=client for default verifier payload=%v", role, payload)
	}
	if verified, _ := sessionPayload["wallet_binding_verified"].(bool); verified {
		t.Fatalf("wallet_binding_verified=%v want=false payload=%v", verified, payload)
	}
}

func TestGPMAuthVerifyCustomSignatureVerifierRejects(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"

	svc.gpmAuthSignatureVerifier = func(gpmWalletChallenge, string, string, string) error {
		return errors.New("signature verification rejected by test verifier")
	}

	challengeBody := `{"wallet_address":"cosmos1customreject","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("challenge message missing: %v", payload)
	}
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1customreject",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "rejected by test verifier") {
		t.Fatalf("error=%q want verifier rejection message payload=%v", errMsg, payload)
	}
	if _, ok := payload["session_token"]; ok {
		t.Fatalf("session_token unexpectedly present payload=%v", payload)
	}
}

func TestGPMAuthVerifyConfiguredVerifierCommandAllowsValidSignature(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCommand = true
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature("signed-proof-value", "bad-signature", 11)

	challengeBody := `{"wallet_address":"cosmos1cmdallow","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}

	verifyBody := `{"wallet_address":"cosmos1cmdallow","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
		t.Fatalf("session_token missing payload=%v", payload)
	}
}

func TestGPMAuthVerifyUnboundCryptoProofCannotUnlockEntitlements(t *testing.T) {
	t.Setenv("GPM_DEFAULT_CLIENT_TIER", "3")
	t.Setenv("GPM_DEFAULT_STAKE_SATISFIED", "1")
	t.Setenv("GPM_DEFAULT_PREPAID_BALANCE_SATISFIED", "1")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	wallet := "cosmos1unboundoperator"
	svc.gpmState.upsertOperator(gpmOperatorApplication{
		WalletAddress:   wallet,
		ChainOperatorID: "operator-unbound-1",
		Status:          "approved",
		UpdatedAt:       time.Now().UTC(),
	})

	challengeBody := `{"wallet_address":"` + wallet + `","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	challengeMessage, _ := payload["message"].(string)
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	verifyRequest := map[string]any{
		"wallet_address":            wallet,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	session, _ := payload["session"].(map[string]any)
	if got, _ := session["role"].(string); got != "client" {
		t.Fatalf("role=%q want=client payload=%v", got, payload)
	}
	if got, _ := session["wallet_binding_verified"].(bool); got {
		t.Fatalf("wallet_binding_verified=%v want=false payload=%v", got, payload)
	}
	if got := intFromAny(session["client_tier"]); got != 1 {
		t.Fatalf("client_tier=%d want=1 payload=%v", got, payload)
	}
	if got, _ := session["stake_satisfied"].(bool); got {
		t.Fatalf("stake_satisfied=%v want=false payload=%v", got, payload)
	}
	if got, _ := session["prepaid_balance_satisfied"].(bool); got {
		t.Fatalf("prepaid_balance_satisfied=%v want=false payload=%v", got, payload)
	}
	if got, _ := session["chain_operator_id"].(string); got != "" {
		t.Fatalf("chain_operator_id=%q want empty payload=%v", got, payload)
	}
}

func TestGPMAuthVerifyStrictCryptoProofRequiresWalletBoundVerifier(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true

	challengeBody := `{"wallet_address":"cosmos1strictcryptounbound","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	challengeMessage, _ := payload["message"].(string)
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1strictcryptounbound",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            challengeMessage,
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "wallet-bound signature verifier command is required") {
		t.Fatalf("error=%q want wallet-bound verifier requirement payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyStrictModeRequiresConfiguredVerifierCommand(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCommand = true
	svc.gpmAuthVerifyCommand = ""
	svc.gpmAuditLogPath = filepath.Join(t.TempDir(), "gpm_audit.jsonl")

	challengeBody := `{"wallet_address":"cosmos1cmdstrictmissing","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}

	verifyBody := `{"wallet_address":"cosmos1cmdstrictmissing","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "signature verifier command is required by policy") {
		t.Fatalf("error=%q want strict-policy message payload=%v", errMsg, payload)
	}
	if _, ok := payload["session_token"]; ok {
		t.Fatalf("session_token unexpectedly present payload=%v", payload)
	}
	records := readAuditLogRecords(t, svc.gpmAuditLogPath)
	var failureRecord map[string]any
	for _, record := range records {
		if event, _ := record["event"].(string); event == "auth_verify_failed" {
			failureRecord = record
		}
	}
	if failureRecord == nil {
		t.Fatalf("missing auth_verify_failed audit record records=%v", records)
	}
	fields, _ := failureRecord["fields"].(map[string]any)
	if got, _ := fields["wallet_address"].(string); got != "cosmos1cmdstrictmissing" {
		t.Fatalf("audit wallet_address=%q want=cosmos1cmdstrictmissing fields=%v", got, fields)
	}
	if got, _ := fields["wallet_provider"].(string); got != "keplr" {
		t.Fatalf("audit wallet_provider=%q want=keplr fields=%v", got, fields)
	}
	if got, _ := fields["challenge_id"].(string); got != challengeID {
		t.Fatalf("audit challenge_id=%q want=%q fields=%v", got, challengeID, fields)
	}
	if got, _ := fields["failure_reason_code"].(string); got != "verifier_command_required" {
		t.Fatalf("audit failure_reason_code=%q want=verifier_command_required fields=%v", got, fields)
	}
	if got, _ := fields["failure_reason_category"].(string); got != "policy" {
		t.Fatalf("audit failure_reason_category=%q want=policy fields=%v", got, fields)
	}
	if _, ok := fields["signature"]; ok {
		t.Fatalf("audit fields unexpectedly include signature: %v", fields)
	}
}

func TestGPMAuthVerifyProductionDefaultRequireCommandFailsClosedWhenCommandUnset(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "1")
	t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", "")
	t.Setenv("GPM_PRODUCTION_MODE", "1")
	t.Setenv("TDPN_PRODUCTION_MODE", "")
	t.Setenv("GPM_AUTH_VERIFY_COMMAND", "")
	t.Setenv("TDPN_AUTH_VERIFY_COMMAND", "")
	t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "")
	t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
	t.Setenv("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "0")
	t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", "")
	t.Setenv("GPM_STATE_STORE_PATH", filepath.Join(tmpDir, "gpm_state.json"))
	t.Setenv("GPM_AUDIT_LOG_PATH", filepath.Join(tmpDir, "gpm_audit.jsonl"))

	svc := New()
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	if !svc.gpmAuthVerifyRequireCommand {
		t.Fatalf("gpmAuthVerifyRequireCommand=%t want=true", svc.gpmAuthVerifyRequireCommand)
	}
	if svc.gpmAuthVerifyRequireCmdSource != "production-default" {
		t.Fatalf("gpmAuthVerifyRequireCmdSource=%q want=production-default", svc.gpmAuthVerifyRequireCmdSource)
	}

	challengeBody := `{"wallet_address":"cosmos1prodstrictcmd","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("challenge message missing: %v", payload)
	}

	verifyBody := `{"wallet_address":"cosmos1prodstrictcmd","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value","signature_kind":"sign_arbitrary","signature_source":"wallet_extension","signed_message":"` + challengeMessage + `"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "signature verifier command is required by policy") {
		t.Fatalf("error=%q want strict-policy message payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyConfiguredVerifierCommandPropagatesSignatureMetadata(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	expectedMetadata := gpmAuthSignatureMetadata{
		SignatureKind:          "eip191",
		SignaturePublicKeyType: "secp256k1",
		SignatureSource:        "wallet_extension",
		ChainID:                "evm-11155111",
		SignatureEnvelope:      "envelope-v1",
	}

	challengeBody := `{"wallet_address":"cosmos1cmdmeta","wallet_provider":"keplr","chain_id":"evm-11155111"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("message missing: %v", payload)
	}
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	expectedMetadata.SignaturePublicKey = publicKey
	expectedMetadata.SignedMessage = challengeMessage
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignatureMetadata(signature, expectedMetadata, "bad-signature-metadata", 13)

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1cmdmeta",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_kind":            "eip191",
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signature_source":          "wallet_extension",
		"chain_id":                  "evm-11155111",
		"signed_message":            challengeMessage,
		"signature_envelope":        "envelope-v1",
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
		t.Fatalf("session_token missing payload=%v", payload)
	}
}

func TestGPMAuthVerifyConfiguredVerifierCommandAcceptsLegacyPublicKeyAliases(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	expectedMetadata := gpmAuthSignatureMetadata{
		SignatureKind:          "eip191",
		SignaturePublicKeyType: "secp256k1",
		SignatureSource:        "wallet_extension",
		ChainID:                "evm-11155111",
		SignatureEnvelope:      "envelope-v1",
	}

	challengeBody := `{"wallet_address":"cosmos1cmdmetaalias","wallet_provider":"keplr","chain_id":"evm-11155111"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("message missing: %v", payload)
	}
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
	expectedMetadata.SignaturePublicKey = publicKey
	expectedMetadata.SignedMessage = challengeMessage
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignatureMetadata(signature, expectedMetadata, "bad-signature-metadata", 13)

	verifyRequest := map[string]any{
		"wallet_address":     "cosmos1cmdmetaalias",
		"wallet_provider":    "keplr",
		"challenge_id":       challengeID,
		"signature":          signature,
		"signature_kind":     "eip191",
		"public_key":         publicKey,
		"public_key_type":    "secp256k1",
		"signature_source":   "wallet_extension",
		"chain_id":           "evm-11155111",
		"signed_message":     challengeMessage,
		"signature_envelope": "envelope-v1",
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
		t.Fatalf("session_token missing payload=%v", payload)
	}
}

func TestGPMAuthVerifyConfiguredVerifierCommandCanonicalPublicKeyMetadataTakesPrecedence(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	expectedMetadata := gpmAuthSignatureMetadata{
		SignatureKind:          "eip191",
		SignaturePublicKeyType: "secp256k1",
		SignatureSource:        "wallet_extension",
		ChainID:                "evm-11155111",
		SignatureEnvelope:      "envelope-v1",
	}

	challengeBody := `{"wallet_address":"cosmos1cmdmetaprefer","wallet_provider":"keplr","chain_id":"evm-11155111"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("message missing: %v", payload)
	}
	signature, canonicalPublicKey := deterministicSecp256k1Proof(challengeMessage)
	expectedMetadata.SignaturePublicKey = canonicalPublicKey
	expectedMetadata.SignedMessage = challengeMessage
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignatureMetadata(signature, expectedMetadata, "bad-signature-metadata", 13)

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1cmdmetaprefer",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_kind":            "eip191",
		"signature_public_key":      canonicalPublicKey,
		"public_key":                "04legacyignored",
		"signature_public_key_type": "secp256k1",
		"public_key_type":           "ed25519",
		"signature_source":          "wallet_extension",
		"chain_id":                  "evm-11155111",
		"signed_message":            challengeMessage,
		"signature_envelope":        "envelope-v1",
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
		t.Fatalf("session_token missing payload=%v", payload)
	}
}

func TestGPMAuthVerifyAcceptsKnownOptionalSignatureMetadataValues(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"

	challengeBody := `{"wallet_address":"cosmos1metaallow","wallet_provider":"keplr","chain_id":"mesh-mainnet-1"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	challengeMessage, _ := payload["message"].(string)
	if strings.TrimSpace(challengeMessage) == "" {
		t.Fatalf("message missing: %v", payload)
	}
	signature, publicKey := deterministicSecp256k1Proof(challengeMessage)

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1metaallow",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_kind":            "sign_arbitrary",
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signature_source":          "manual",
		"chain_id":                  "mesh-mainnet-1",
		"signed_message":            challengeMessage,
		"signature_envelope": map[string]any{
			"pub_key": map[string]any{
				"type":  "secp256k1",
				"value": "base64-key",
			},
			"signature": "base64-sig",
		},
	}
	verifyBodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}

	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
		t.Fatalf("session_token missing payload=%v", payload)
	}
}

func TestGPMAuthVerifyRejectsInvalidOptionalSignatureMetadata(t *testing.T) {
	testCases := []struct {
		name          string
		metadata      map[string]any
		wantErrorText string
	}{
		{
			name: "signed_message mismatch",
			metadata: map[string]any{
				"signed_message": "not-the-issued-message",
			},
			wantErrorText: "signed_message does not match issued challenge message",
		},
		{
			name: "unknown signature_kind",
			metadata: map[string]any{
				"signature_kind": "typed_data",
			},
			wantErrorText: "unsupported signature_kind",
		},
		{
			name: "unknown signature_source",
			metadata: map[string]any{
				"signature_source": "hardware_wallet",
			},
			wantErrorText: "unsupported signature_source",
		},
		{
			name: "unknown signature_public_key_type",
			metadata: map[string]any{
				"signature_public_key_type": "rsa",
			},
			wantErrorText: "unsupported signature_public_key_type",
		},
		{
			name: "signature_envelope too long",
			metadata: map[string]any{
				"signature_envelope": strings.Repeat("A", gpmAuthSignatureEnvelopeMaxLen+1),
			},
			wantErrorText: "signature_envelope is too long",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.gpmState = newGPMRuntimeState()
			svc.gpmRoleDefault = "client"

			challengeBody := `{"wallet_address":"cosmos1metareject","wallet_provider":"keplr"}`
			code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
			if code != http.StatusOK {
				t.Fatalf("challenge status=%d body=%v", code, payload)
			}
			challengeID, _ := payload["challenge_id"].(string)
			if strings.TrimSpace(challengeID) == "" {
				t.Fatalf("challenge_id missing: %v", payload)
			}

			verifyRequest := map[string]any{
				"wallet_address":  "cosmos1metareject",
				"wallet_provider": "keplr",
				"challenge_id":    challengeID,
				"signature":       "signed-proof-value",
			}
			for key, value := range tc.metadata {
				verifyRequest[key] = value
			}
			verifyBodyBytes, err := json.Marshal(verifyRequest)
			if err != nil {
				t.Fatalf("json marshal verify request: %v", err)
			}

			code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
			if code != http.StatusUnauthorized {
				t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
			}
			errMsg, _ := payload["error"].(string)
			if !strings.Contains(errMsg, tc.wantErrorText) {
				t.Fatalf("error=%q want contains %q payload=%v", errMsg, tc.wantErrorText, payload)
			}
		})
	}
}

func TestGPMAuthVerifyCryptographicProofWithOptionalMetadata(t *testing.T) {
	t.Run("accepts valid ed25519 proof when metadata is provided", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"

		challengeBody := `{"wallet_address":"cosmos1ed25519pass","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}

		signature, publicKey := deterministicEd25519Proof(challengeMessage)
		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1ed25519pass",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "ed25519",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusOK {
			t.Fatalf("verify status=%d body=%v", code, payload)
		}
		if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
			t.Fatalf("session_token missing payload=%v", payload)
		}
	})

	t.Run("rejects invalid ed25519 proof when metadata is provided", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"

		challengeBody := `{"wallet_address":"cosmos1ed25519fail","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}

		signature, publicKey := deterministicEd25519Proof("different-message")
		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1ed25519fail",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "ed25519",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "ed25519 signature verification failed") {
			t.Fatalf("error=%q want ed25519 verification failure payload=%v", errMsg, payload)
		}
	})

	t.Run("accepts valid secp256k1 proof when metadata is provided", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"

		challengeBody := `{"wallet_address":"cosmos1secp256k1pass","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}
		signature, publicKey := deterministicSecp256k1Proof(challengeMessage)

		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1secp256k1pass",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "secp256k1",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusOK {
			t.Fatalf("verify status=%d body=%v", code, payload)
		}
		if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
			t.Fatalf("session_token missing payload=%v", payload)
		}
	})

	t.Run("rejects invalid secp256k1 proof when metadata is provided", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"

		challengeBody := `{"wallet_address":"cosmos1secp256k1fail","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}
		signature, publicKey := deterministicSecp256k1Proof("different-message")

		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1secp256k1fail",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "secp256k1",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "secp256k1 signature verification failed") {
			t.Fatalf("error=%q want secp256k1 verification failure payload=%v", errMsg, payload)
		}
	})

	t.Run("fails closed when cryptographic proof metadata is missing and no external verifier is configured", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"

		challengeBody := `{"wallet_address":"cosmos1compatmissingproof","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}

		verifyBody := `{"wallet_address":"cosmos1compatmissingproof","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "cryptographic proof metadata is required when no external verifier is configured") {
			t.Fatalf("error=%q want no-external-verifier cryptographic proof message payload=%v", errMsg, payload)
		}
	})

}

func TestGPMAuthVerifyStrictCryptographicProofPolicy(t *testing.T) {
	t.Run("rejects requests missing cryptographic proof metadata", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireCryptoProof = true

		challengeBody := `{"wallet_address":"cosmos1strictcryptomissing","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}

		verifyBody := `{"wallet_address":"cosmos1strictcryptomissing","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "cryptographic proof metadata is required by policy") {
			t.Fatalf("error=%q want strict-crypto metadata message payload=%v", errMsg, payload)
		}
	})

	t.Run("rejects invalid secp256k1 proofs when strict crypto policy is enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireCryptoProof = true

		challengeBody := `{"wallet_address":"cosmos1strictcryptosecp","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}
		signature, publicKey := deterministicSecp256k1Proof("different-message")

		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1strictcryptosecp",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "secp256k1",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "secp256k1 signature verification failed") {
			t.Fatalf("error=%q want strict secp256k1 verification failure payload=%v", errMsg, payload)
		}
	})

	t.Run("accepts valid secp256k1 proofs when strict crypto policy is enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireCryptoProof = true

		walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")
		challengeBody := `{"wallet_address":"` + walletAddress + `","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}
		signature, publicKey := deterministicSecp256k1Proof(challengeMessage)
		svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature(signature, "bad-signature", 13)

		verifyRequest := map[string]any{
			"wallet_address":            walletAddress,
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "secp256k1",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusOK {
			t.Fatalf("verify status=%d body=%v", code, payload)
		}
		if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
			t.Fatalf("session_token missing payload=%v", payload)
		}
	})

	t.Run("rejects ed25519 proofs for wallet-bound strict crypto policy", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireCryptoProof = true

		challengeBody := `{"wallet_address":"cosmos1strictcryptoed","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}

		signature, publicKey := deterministicEd25519Proof(challengeMessage)
		svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature(signature, "bad-signature", 13)
		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1strictcryptoed",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "ed25519",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound signature verifier") {
			t.Fatalf("error=%q want wallet-bound verifier guidance payload=%v", got, payload)
		}
	})
}

func TestGPMAuthVerifyRequireMetadataPolicy(t *testing.T) {
	t.Run("rejects missing required metadata fields", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireMetadata = true

		challengeBody := `{"wallet_address":"cosmos1policymetadata","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}

		verifyBody := `{"wallet_address":"cosmos1policymetadata","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "signature metadata fields are required by policy") {
			t.Fatalf("error=%q want policy-required metadata message payload=%v", errMsg, payload)
		}
		if !strings.Contains(errMsg, "signature_kind") || !strings.Contains(errMsg, "signature_source") || !strings.Contains(errMsg, "signed_message") {
			t.Fatalf("error=%q want missing field names payload=%v", errMsg, payload)
		}
	})

	t.Run("passes when required metadata fields are provided", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireMetadata = true

		challengeBody := `{"wallet_address":"cosmos1policymetadatapass","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}
		signature, publicKey := deterministicSecp256k1Proof(challengeMessage)

		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1policymetadatapass",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_kind":            "eip191",
			"signature_source":          "manual",
			"signed_message":            challengeMessage,
			"signature_public_key":      publicKey,
			"signature_public_key_type": "secp256k1",
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusOK {
			t.Fatalf("verify status=%d body=%v", code, payload)
		}
		if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
			t.Fatalf("session_token missing payload=%v", payload)
		}
	})
}

func TestGPMAuthVerifyRequireWalletExtensionSourcePolicy(t *testing.T) {
	t.Run("rejects missing signature_source when policy enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireWalletExt = true

		challengeBody := `{"wallet_address":"cosmos1policywalletsrc","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}

		verifyBody := `{"wallet_address":"cosmos1policywalletsrc","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "must be explicitly provided as wallet_extension by policy") {
			t.Fatalf("error=%q want explicit-wallet_extension message payload=%v", errMsg, payload)
		}
	})

	t.Run("rejects non-wallet_extension signature_source when policy enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireWalletExt = true

		challengeBody := `{"wallet_address":"cosmos1policywalletsrcmanual","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}

		verifyRequest := map[string]any{
			"wallet_address":   "cosmos1policywalletsrcmanual",
			"wallet_provider":  "keplr",
			"challenge_id":     challengeID,
			"signature":        "signed-proof-value",
			"signature_source": "manual",
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusUnauthorized {
			t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "signature_source must be wallet_extension by policy") {
			t.Fatalf("error=%q want wallet_extension-only message payload=%v", errMsg, payload)
		}
	})

	t.Run("passes with wallet_extension signature_source when policy enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmRoleDefault = "client"
		svc.gpmAuthVerifyRequireWalletExt = true

		challengeBody := `{"wallet_address":"cosmos1policywalletsrcpass","wallet_provider":"keplr"}`
		code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
		if code != http.StatusOK {
			t.Fatalf("challenge status=%d body=%v", code, payload)
		}
		challengeID, _ := payload["challenge_id"].(string)
		if strings.TrimSpace(challengeID) == "" {
			t.Fatalf("challenge_id missing: %v", payload)
		}
		challengeMessage, _ := payload["message"].(string)
		if strings.TrimSpace(challengeMessage) == "" {
			t.Fatalf("message missing: %v", payload)
		}
		signature, publicKey := deterministicSecp256k1Proof(challengeMessage)

		verifyRequest := map[string]any{
			"wallet_address":            "cosmos1policywalletsrcpass",
			"wallet_provider":           "keplr",
			"challenge_id":              challengeID,
			"signature":                 signature,
			"signature_source":          "wallet_extension",
			"signature_public_key":      publicKey,
			"signature_public_key_type": "secp256k1",
			"signed_message":            challengeMessage,
		}
		verifyBodyBytes, err := json.Marshal(verifyRequest)
		if err != nil {
			t.Fatalf("json marshal verify request: %v", err)
		}

		code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(verifyBodyBytes))
		if code != http.StatusOK {
			t.Fatalf("verify status=%d body=%v", code, payload)
		}
		if got, _ := payload["session_token"].(string); strings.TrimSpace(got) == "" {
			t.Fatalf("session_token missing payload=%v", payload)
		}
	})
}

func TestGPMAuthVerifyConfiguredVerifierCommandRejectsSignature(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature("signed-proof-value", "bad-signature", 12)
	svc.gpmAuditLogPath = filepath.Join(t.TempDir(), "gpm_audit.jsonl")

	challengeBody := `{"wallet_address":"cosmos1cmdreject","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}

	verifyBody := `{"wallet_address":"cosmos1cmdreject","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value-invalid"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "rejected signature") {
		t.Fatalf("error=%q want rejected-signature marker payload=%v", errMsg, payload)
	}
	if strings.Contains(errMsg, "bad-signature") {
		t.Fatalf("error=%q leaked verifier command output payload=%v", errMsg, payload)
	}
	records := readAuditLogRecords(t, svc.gpmAuditLogPath)
	var failureRecord map[string]any
	for _, record := range records {
		if event, _ := record["event"].(string); event == "auth_verify_failed" {
			failureRecord = record
		}
	}
	if failureRecord == nil {
		t.Fatalf("missing auth_verify_failed audit record records=%v", records)
	}
	fields, _ := failureRecord["fields"].(map[string]any)
	if got, _ := fields["wallet_address"].(string); got != "cosmos1cmdreject" {
		t.Fatalf("audit wallet_address=%q want=cosmos1cmdreject fields=%v", got, fields)
	}
	if got, _ := fields["wallet_provider"].(string); got != "keplr" {
		t.Fatalf("audit wallet_provider=%q want=keplr fields=%v", got, fields)
	}
	if got, _ := fields["challenge_id"].(string); got != challengeID {
		t.Fatalf("audit challenge_id=%q want=%q fields=%v", got, challengeID, fields)
	}
	if got, _ := fields["failure_reason_code"].(string); got != "verifier_command_error" {
		t.Fatalf("audit failure_reason_code=%q want=verifier_command_error fields=%v", got, fields)
	}
	if got, _ := fields["failure_reason_category"].(string); got != "external_verifier" {
		t.Fatalf("audit failure_reason_category=%q want=external_verifier fields=%v", got, fields)
	}
	if _, ok := fields["signature"]; ok {
		t.Fatalf("audit fields unexpectedly include signature: %v", fields)
	}
}

func TestGPMSessionRefreshAndRevoke(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	const originalToken = "gpm-session-token-original"
	svc.gpmState.putSession(gpmSession{
		Token:          originalToken,
		WalletAddress:  "cosmos1sessionuser",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	refreshBody := `{"session_token":"` + originalToken + `","action":"refresh"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", refreshBody)
	if code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", code, payload)
	}
	action, _ := payload["action"].(string)
	if action != "refresh" {
		t.Fatalf("action=%q want=refresh payload=%v", action, payload)
	}
	refreshedToken, _ := payload["session_token"].(string)
	if strings.TrimSpace(refreshedToken) == "" {
		t.Fatalf("session_token missing after refresh payload=%v", payload)
	}
	if refreshedToken == originalToken {
		t.Fatalf("session_token was not rotated old=%q new=%q", originalToken, refreshedToken)
	}
	sessionReconciled, ok := payload["session_reconciled"].(bool)
	if !ok {
		t.Fatalf("session_reconciled missing in payload=%v", payload)
	}
	if sessionReconciled {
		t.Fatalf("session_reconciled=%v want=false payload=%v", sessionReconciled, payload)
	}
	if _, ok := svc.gpmState.getSession(originalToken, time.Now().UTC()); ok {
		t.Fatalf("expected original token to be removed after refresh")
	}
	if _, ok := svc.gpmState.getSession(refreshedToken, time.Now().UTC()); !ok {
		t.Fatalf("expected refreshed token to exist")
	}

	revokeBody := `{"session_token":"` + refreshedToken + `","action":"revoke"}`
	code, payload = callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", revokeBody)
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, payload)
	}
	revokeAction, _ := payload["action"].(string)
	if revokeAction != "revoke" {
		t.Fatalf("action=%q want=revoke payload=%v", revokeAction, payload)
	}
	revoked, _ := payload["revoked"].(bool)
	if !revoked {
		t.Fatalf("expected revoked=true payload=%v", payload)
	}
	if _, ok := svc.gpmState.getSession(refreshedToken, time.Now().UTC()); ok {
		t.Fatalf("expected refreshed token to be removed after revoke")
	}

	statusBody := `{"session_token":"` + refreshedToken + `","action":"status"}`
	code, payload = callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
	if code != http.StatusNotFound {
		t.Fatalf("expected revoked token status 404 got=%d payload=%v", code, payload)
	}
}

func TestGPMSessionStatusRequiresReadAuthBeforeBodyDecode(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.authToken = strongLocalAPIAuthToken

	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", "{")
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated malformed body status=%d want=%d payload=%v", code, http.StatusUnauthorized, payload)
	}
	if got, _ := payload["error"].(string); got != "unauthorized" {
		t.Fatalf("error=%q want unauthorized payload=%v", got, payload)
	}

	code, payload = callJSONHandlerWithHeaders(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", "{", map[string]string{
		"Authorization": "Bearer " + strongLocalAPIAuthToken,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("authenticated malformed body status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
}

func TestGPMSessionRefreshRejectsProductionMode(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmConnectPolicyMode = "production"
	now := time.Now().UTC()
	const token = "gpm-session-token-production-refresh"
	svc.gpmState.putSession(gpmSession{
		Token:                     token,
		WalletAddress:             "cosmos1prodrefresh",
		WalletProvider:            "keplr",
		Role:                      "client",
		WalletBindingVerified:     true,
		ClientTier:                3,
		StakeSatisfied:            true,
		PrepaidBalanceSatisfied:   true,
		EntitlementEvidenceSource: "chain",
		CreatedAt:                 now,
		ExpiresAt:                 now.Add(time.Hour),
	})

	body := `{"session_token":"` + token + `","action":"refresh"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", body)
	if code != http.StatusForbidden {
		t.Fatalf("refresh status=%d want=%d body=%v", code, http.StatusForbidden, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "fresh wallet challenge") {
		t.Fatalf("error=%q want fresh-wallet guidance payload=%v", got, payload)
	}
	if _, ok := svc.gpmState.getSession(token, time.Now().UTC()); !ok {
		t.Fatalf("rejected production refresh should not delete the existing session")
	}
}

func TestGPMSessionRefreshRejectsSessionOutsideCurrentWalletChainPolicy(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmAuthExpectedChainID = "gpm-testnet-1"
	now := time.Now().UTC()
	const token = "gpm-session-token-old-chain"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1oldchainuser",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	body := `{"session_token":"` + token + `","action":"refresh"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", body)
	if code != http.StatusForbidden {
		t.Fatalf("refresh status=%d want=%d body=%v", code, http.StatusForbidden, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "session chain_id is missing") {
		t.Fatalf("error=%q want session chain policy guidance payload=%v", got, payload)
	}
	if _, ok := svc.gpmState.getSession(token, time.Now().UTC()); !ok {
		t.Fatalf("rejected refresh should not delete the existing session")
	}
}

func TestGPMSessionUseRejectsSessionOutsideCurrentWalletChainPolicy(t *testing.T) {
	t.Run("contribution status rejects stale chain session", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmAuthExpectedChainID = "gpm-testnet-1"
		const token = "gpm-stale-chain-contribution"
		svc.gpmState.putSession(gpmSession{
			Token:                     token,
			WalletAddress:             "cosmos1stalechaincontrib",
			WalletProvider:            "keplr",
			Role:                      "client",
			WalletBindingVerified:     true,
			EntitlementEvidenceSource: "chain",
			ClientTier:                3,
			StakeSatisfied:            true,
			PrepaidBalanceSatisfied:   true,
			CreatedAt:                 time.Now().UTC(),
			ExpiresAt:                 time.Now().UTC().Add(time.Hour),
		})

		code, payload := callJSONHandler(t, svc.handleGPMContributionStatus, http.MethodGet, "/v1/gpm/contribution/status?session_token="+token, "")
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session chain_id is missing") {
			t.Fatalf("error=%q want stale chain policy guidance payload=%v", got, payload)
		}
	})

	t.Run("service mutation gives stale chain policy guidance", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmAuthExpectedChainID = "gpm-testnet-1"
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:                 "gpm-stale-chain-operator",
			Role:                  "operator",
			WalletAddress:         "cosmos1stalechainoperator",
			WalletProvider:        "keplr",
			WalletBindingVerified: true,
			ChainOperatorID:       "operator-stale-chain",
			CreatedAt:             time.Now().UTC(),
			ExpiresAt:             time.Now().UTC().Add(time.Hour),
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:          "cosmos1stalechainoperator",
			ChainOperatorID:        "operator-stale-chain",
			Status:                 "approved",
			ApprovalEvidenceSource: "chain-governance",
			UpdatedAt:              time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-stale-chain-operator"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session no longer satisfies wallet auth policy") {
			t.Fatalf("error=%q want stale policy guidance payload=%v", got, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("stale chain session should not execute commands, got=%v", cmds)
		}
	})
}

func TestGPMSessionUseRejectsSessionMintedUnderDifferentAuthPolicy(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMTestSession(t, svc, "gpm-policy-fingerprint-session", "cosmos1policyfingerprint", 2, true, true)
	session, ok, err := svc.gpmSessionFromToken(token)
	if err != nil {
		t.Fatalf("seeded session should satisfy baseline policy: %v", err)
	}
	if !ok {
		t.Fatal("expected seeded session")
	}
	session.AuthPolicyFingerprint = svc.gpmCurrentAuthPolicyFingerprint()
	svc.gpmState.putSession(session)

	svc.gpmAuthVerifyRequireCryptoProof = true
	_, ok, err = svc.gpmSessionFromToken(token)
	if err == nil {
		t.Fatal("expected stale auth policy fingerprint rejection")
	}
	if ok {
		t.Fatal("session minted under stale auth policy should not be accepted")
	}
	if !strings.Contains(err.Error(), "different wallet auth policy") {
		t.Fatalf("error=%q want auth policy fingerprint guidance", err)
	}
}

func TestGPMSessionStatusReconcilesStaleOperatorSessionToClient(t *testing.T) {
	testCases := []struct {
		name string
		app  *gpmOperatorApplication
	}{
		{
			name: "when operator application is missing",
			app:  nil,
		},
		{
			name: "when operator application is rejected",
			app: &gpmOperatorApplication{
				WalletAddress:   "cosmos1staleoperator",
				ChainOperatorID: "operator-stale-1",
				Status:          "rejected",
				UpdatedAt:       time.Now().UTC(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.gpmState = newGPMRuntimeState()

			const sessionToken = "gpm-session-stale-operator"
			now := time.Now().UTC()
			svc.gpmState.putSession(gpmSession{
				Token:           sessionToken,
				WalletAddress:   "cosmos1staleoperator",
				WalletProvider:  "keplr",
				Role:            "operator",
				ChainOperatorID: "operator-stale-1",
				CreatedAt:       now,
				ExpiresAt:       now.Add(time.Hour),
			})
			if tc.app != nil {
				svc.gpmState.upsertOperator(*tc.app)
			}

			statusBody := `{"session_token":"` + sessionToken + `","action":"status"}`
			code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
			if code != http.StatusOK {
				t.Fatalf("session status=%d payload=%v", code, payload)
			}

			sessionReconciled, ok := payload["session_reconciled"].(bool)
			if !ok {
				t.Fatalf("session_reconciled missing payload=%v", payload)
			}
			if !sessionReconciled {
				t.Fatalf("session_reconciled=%v want=true payload=%v", sessionReconciled, payload)
			}

			sessionPayload, _ := payload["session"].(map[string]any)
			if role, _ := sessionPayload["role"].(string); role != "client" {
				t.Fatalf("session.role=%q want=client payload=%v", role, payload)
			}
			if chainOperatorID, _ := sessionPayload["chain_operator_id"].(string); strings.TrimSpace(chainOperatorID) != "" {
				t.Fatalf("session.chain_operator_id=%q want empty payload=%v", chainOperatorID, payload)
			}

			storedSession, ok := svc.gpmState.getSession(sessionToken, time.Now().UTC())
			if !ok {
				t.Fatalf("expected session to remain present after reconciliation")
			}
			if storedSession.Role != "client" {
				t.Fatalf("stored session role=%q want=client", storedSession.Role)
			}
			if strings.TrimSpace(storedSession.ChainOperatorID) != "" {
				t.Fatalf("stored session chain_operator_id=%q want empty", storedSession.ChainOperatorID)
			}
		})
	}
}

func TestGPMSessionStatusUpgradesClientSessionToOperatorWhenApproved(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()

	const sessionToken = "gpm-session-upgrade-operator"
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:                 sessionToken,
		WalletAddress:         "cosmos1upgradeoperator",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})
	svc.gpmState.upsertOperator(gpmOperatorApplication{
		WalletAddress:   "cosmos1upgradeoperator",
		ChainOperatorID: "operator-approved-123",
		Status:          "approved",
		UpdatedAt:       now,
	})

	statusBody := `{"session_token":"` + sessionToken + `","action":"status"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
	if code != http.StatusOK {
		t.Fatalf("session status=%d payload=%v", code, payload)
	}

	sessionReconciled, ok := payload["session_reconciled"].(bool)
	if !ok {
		t.Fatalf("session_reconciled missing payload=%v", payload)
	}
	if !sessionReconciled {
		t.Fatalf("session_reconciled=%v want=true payload=%v", sessionReconciled, payload)
	}

	sessionPayload, _ := payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "operator" {
		t.Fatalf("session.role=%q want=operator payload=%v", role, payload)
	}
	if chainOperatorID, _ := sessionPayload["chain_operator_id"].(string); chainOperatorID != "operator-approved-123" {
		t.Fatalf("session.chain_operator_id=%q want=operator-approved-123 payload=%v", chainOperatorID, payload)
	}

	storedSession, ok := svc.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		t.Fatalf("expected session to remain present after reconciliation")
	}
	if storedSession.Role != "operator" {
		t.Fatalf("stored session role=%q want=operator", storedSession.Role)
	}
	if storedSession.ChainOperatorID != "operator-approved-123" {
		t.Fatalf("stored session chain_operator_id=%q want=operator-approved-123", storedSession.ChainOperatorID)
	}
}

func TestGPMOperatorDecisionOnlyPromotesWalletBoundSessions(t *testing.T) {
	state := newGPMRuntimeState()
	now := time.Now().UTC()
	const wallet = "cosmos1operatorapproval"
	state.putSession(gpmSession{
		Token:                 "gpm-bound-operator-session",
		WalletAddress:         wallet,
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})
	state.putSession(gpmSession{
		Token:          "gpm-unbound-operator-session",
		WalletAddress:  wallet,
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	if changed := state.applyOperatorDecisionToSessions(wallet, true, "operator-approved-123"); !changed {
		t.Fatal("expected approval decision to update at least one session")
	}

	bound, ok := state.getSession("gpm-bound-operator-session", now)
	if !ok {
		t.Fatal("expected bound session to remain present")
	}
	if bound.Role != "operator" || bound.ChainOperatorID != "operator-approved-123" {
		t.Fatalf("bound session not promoted correctly: %+v", bound)
	}
	unbound, ok := state.getSession("gpm-unbound-operator-session", now)
	if !ok {
		t.Fatal("expected unbound session to remain present")
	}
	if unbound.Role != "client" || strings.TrimSpace(unbound.ChainOperatorID) != "" {
		t.Fatalf("unbound session should stay client without chain binding: %+v", unbound)
	}
}

func TestGPMSessionStatusDoesNotUpgradeUnboundSessionWhenApproved(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()

	const sessionToken = "gpm-session-unbound-upgrade-blocked"
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:          sessionToken,
		WalletAddress:  "cosmos1unboundupgrade",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})
	svc.gpmState.upsertOperator(gpmOperatorApplication{
		WalletAddress:   "cosmos1unboundupgrade",
		ChainOperatorID: "operator-approved-123",
		Status:          "approved",
		UpdatedAt:       now,
	})

	statusBody := `{"session_token":"` + sessionToken + `","action":"status"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
	if code != http.StatusOK {
		t.Fatalf("session status=%d payload=%v", code, payload)
	}
	if sessionReconciled, _ := payload["session_reconciled"].(bool); sessionReconciled {
		t.Fatalf("unbound approved session should not be reconciled to operator payload=%v", payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "client" {
		t.Fatalf("session.role=%q want=client payload=%v", role, payload)
	}

	storedSession, ok := svc.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		t.Fatal("expected session to remain present")
	}
	if storedSession.Role != "client" || strings.TrimSpace(storedSession.ChainOperatorID) != "" {
		t.Fatalf("stored unbound session should remain client without chain id: %+v", storedSession)
	}
}

func TestGPMSessionActionRejectsUnknownAction(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:          "gpm-session-token-invalid-action",
		WalletAddress:  "cosmos1sessionaction",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	body := `{"session_token":"gpm-session-token-invalid-action","action":"rotate"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", body)
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "action must be one of") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMClientRegisterUsesManifestAndPersistsSessionConnectSecrets(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	primaryBootstrapDirectory := "https://directory-primary.globalprivatemesh.example:8081"
	secondaryBootstrapDirectory := "https://directory-secondary.globalprivatemesh.example:8081"
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{primaryBootstrapDirectory, secondaryBootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token"
	svc.gpmState.putSession(gpmSession{
		Token:                   token,
		WalletAddress:           "cosmos1registeredclient",
		WalletProvider:          "keplr",
		Role:                    "client",
		WalletBindingVerified:   true,
		ClientTier:              2,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		CreatedAt:               now,
		ExpiresAt:               now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","bootstrap_directory":"` + secondaryBootstrapDirectory + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusOK {
		t.Fatalf("register status=%d body=%v", code, payload)
	}

	profile, _ := payload["profile"].(map[string]any)
	gotBootstrap, _ := profile["bootstrap_directory"].(string)
	if gotBootstrap != secondaryBootstrapDirectory {
		t.Fatalf("profile bootstrap_directory=%q want=%q", gotBootstrap, secondaryBootstrapDirectory)
	}
	gotProfile, _ := profile["path_profile"].(string)
	if gotProfile != "3hop" {
		t.Fatalf("profile path_profile=%q want=3hop", gotProfile)
	}

	session, ok := svc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatal("expected session to persist after registration")
	}
	if session.BootstrapDirectory != secondaryBootstrapDirectory {
		t.Fatalf("session bootstrap_directory=%q want=%q", session.BootstrapDirectory, secondaryBootstrapDirectory)
	}
	if len(session.BootstrapDirectories) != 2 {
		t.Fatalf("session bootstrap_directories=%v want two directories", session.BootstrapDirectories)
	}
	if session.BootstrapDirectories[0] != primaryBootstrapDirectory || session.BootstrapDirectories[1] != secondaryBootstrapDirectory {
		t.Fatalf("session bootstrap_directories=%v want=%v", session.BootstrapDirectories, []string{primaryBootstrapDirectory, secondaryBootstrapDirectory})
	}
	if !strings.HasPrefix(session.InviteKey, "wallet:") {
		t.Fatalf("session invite_key=%q want wallet:* fallback", session.InviteKey)
	}
	if session.PathProfile != "3hop" {
		t.Fatalf("session path_profile=%q want=3hop", session.PathProfile)
	}
}

func TestGPMClientRegisterRejectsUnboundWalletSession(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	token := seedGPMUnboundTestSession(t, svc, "gpm-unbound-register-session", "cosmos1unboundregister")

	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", `{
		"session_token":"`+token+`",
		"bootstrap_directory":"https://directory.globalprivatemesh.example:8081"
	}`)
	if code != http.StatusForbidden {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "wallet-bound session is required for client registration") {
		t.Fatalf("error=%q want wallet-bound registration rejection", got)
	}
}

func TestGPMClientRegisterCanonicalizesBootstrapDirectoryBeforeStorageAndComparison(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{"https://Directory.GlobalPrivateMesh.Example:443/"},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token-canonical-bootstrap"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1canonicalclient",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","bootstrap_directory":"https://directory.globalprivatemesh.example/","path_profile":"2hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusOK {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	profile, _ := payload["profile"].(map[string]any)
	if got, _ := profile["bootstrap_directory"].(string); got != "https://directory.globalprivatemesh.example" {
		t.Fatalf("profile.bootstrap_directory=%q want canonical payload=%v", got, payload)
	}
	session, ok := svc.gpmState.getSession(token, now)
	if !ok {
		t.Fatal("expected session to remain valid")
	}
	if session.BootstrapDirectory != "https://directory.globalprivatemesh.example" {
		t.Fatalf("session.BootstrapDirectory=%q want canonical", session.BootstrapDirectory)
	}
	if len(session.BootstrapDirectories) != 1 || session.BootstrapDirectories[0] != "https://directory.globalprivatemesh.example" {
		t.Fatalf("session.BootstrapDirectories=%v want canonical singleton", session.BootstrapDirectories)
	}
}

func TestGPMClientRegisterRejectsTierOneMicroRelayPath(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	bootstrapDirectory := "https://directory.globalprivatemesh.example:8081"
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{bootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token-tier1-3hop"
	svc.gpmState.putSession(gpmSession{
		Token:                   token,
		WalletAddress:           "cosmos1tier1register",
		WalletProvider:          "keplr",
		Role:                    "client",
		WalletBindingVerified:   true,
		ClientTier:              1,
		StakeSatisfied:          true,
		PrepaidBalanceSatisfied: true,
		CreatedAt:               now,
		ExpiresAt:               now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusForbidden {
		t.Fatalf("register status=%d want=%d body=%v", code, http.StatusForbidden, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "Tier 2 or Tier 3") {
		t.Fatalf("error=%q want Tier 2/3 guidance payload=%v", got, payload)
	}
	if canUse, _ := payload["can_use_micro_relays"].(bool); canUse {
		t.Fatalf("can_use_micro_relays=%v want=false payload=%v", canUse, payload)
	}
}

func TestGPMClientStatusEndpointRegistrationStates(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	trustedBootstrap := "https://directory.globalprivatemesh.example:8081"
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{trustedBootstrap},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	svc.gpmState.putSession(gpmSession{
		Token:              "gpm-client-status-registered",
		WalletAddress:      "cosmos1registeredstatus",
		WalletProvider:     "keplr",
		Role:               "client",
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Hour),
		BootstrapDirectory: trustedBootstrap,
		InviteKey:          "inv-registered",
		PathProfile:        "3hop",
	})
	svc.gpmState.putSession(gpmSession{
		Token:          "gpm-client-status-not-registered",
		WalletAddress:  "cosmos1notregisteredstatus",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})
	svc.gpmState.putSession(gpmSession{
		Token:                "gpm-client-status-drifted",
		WalletAddress:        "cosmos1driftedstatus",
		WalletProvider:       "keplr",
		Role:                 "client",
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Hour),
		BootstrapDirectory:   "https://directory.revoked.globalprivatemesh.example:8081",
		BootstrapDirectories: []string{"https://directory.revoked.globalprivatemesh.example:8081"},
		InviteKey:            "inv-drifted",
		PathProfile:          "2hop",
	})

	t.Run("registered", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-registered"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		gotStatus, _ := registration["status"].(string)
		if gotStatus != "registered" {
			t.Fatalf("registration.status=%q want=registered payload=%v", gotStatus, payload)
		}
		gotWallet, _ := registration["wallet_address"].(string)
		if gotWallet != "cosmos1registeredstatus" {
			t.Fatalf("registration.wallet_address=%q want=cosmos1registeredstatus payload=%v", gotWallet, payload)
		}
		gotBootstrap, _ := registration["bootstrap_directory"].(string)
		if gotBootstrap != trustedBootstrap {
			t.Fatalf("registration.bootstrap_directory=%q payload=%v", gotBootstrap, payload)
		}
		gotProfile, _ := registration["path_profile"].(string)
		if gotProfile != "3hop" {
			t.Fatalf("registration.path_profile=%q want=3hop payload=%v", gotProfile, payload)
		}
	})

	t.Run("not_registered", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-not-registered"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		gotStatus, _ := registration["status"].(string)
		if gotStatus != "not_registered" {
			t.Fatalf("registration.status=%q want=not_registered payload=%v", gotStatus, payload)
		}
		gotWallet, _ := registration["wallet_address"].(string)
		if gotWallet != "cosmos1notregisteredstatus" {
			t.Fatalf("registration.wallet_address=%q want=cosmos1notregisteredstatus payload=%v", gotWallet, payload)
		}
		gotBootstrap, _ := registration["bootstrap_directory"].(string)
		if gotBootstrap != "" {
			t.Fatalf("registration.bootstrap_directory=%q want empty payload=%v", gotBootstrap, payload)
		}
		if _, ok := registration["path_profile"]; ok {
			t.Fatalf("registration.path_profile should be omitted payload=%v", payload)
		}
	})

	t.Run("manifest_drift_revoked", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-drifted"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		if got, _ := registration["status"].(string); got != "not_registered" {
			t.Fatalf("registration.status=%q want=not_registered payload=%v", got, payload)
		}
		if got, _ := registration["status_reason"].(string); !strings.Contains(got, "no longer trusted") {
			t.Fatalf("registration.status_reason=%q want trust-revoked guidance payload=%v", got, payload)
		}
		if got, _ := registration["bootstrap_directory"].(string); got != "" {
			t.Fatalf("registration.bootstrap_directory=%q want empty payload=%v", got, payload)
		}
	})

	t.Run("manifest_revalidation_hard_failure_is_degraded", func(t *testing.T) {
		degradedSvc, _ := newFakeService(t, false)
		degradedSvc.gpmState = newGPMRuntimeState()
		degradedSvc.gpmState.putSession(gpmSession{
			Token:                "gpm-client-status-degraded",
			WalletAddress:        "cosmos1degradedstatus",
			WalletProvider:       "keplr",
			Role:                 "client",
			CreatedAt:            now,
			ExpiresAt:            now.Add(time.Hour),
			BootstrapDirectory:   trustedBootstrap,
			BootstrapDirectories: []string{trustedBootstrap},
			InviteKey:            "inv-degraded",
			PathProfile:          "2hop",
		})

		body := `{"session_token":"gpm-client-status-degraded"}`
		code, payload := callJSONHandler(t, degradedSvc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		if got, _ := registration["status"].(string); got != "degraded" {
			t.Fatalf("registration.status=%q want=degraded payload=%v", got, payload)
		}
		if got, _ := registration["status_reason"].(string); !strings.Contains(got, "failed to revalidate") {
			t.Fatalf("registration.status_reason=%q want hard-failure guidance payload=%v", got, payload)
		}
	})

	t.Run("invalid_session", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-missing"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusNotFound {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session not found") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("missing_session_token", func(t *testing.T) {
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session_token is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})
}

func TestGPMServerStatus(t *testing.T) {
	newServerStatusService := func(t *testing.T) *Service {
		t.Helper()
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = lifecycleSuccessCommand("start")
		svc.serviceStop = lifecycleSuccessCommand("stop")
		svc.serviceRestart = lifecycleSuccessCommand("restart")
		return svc
	}
	getReadiness := func(t *testing.T, payload map[string]any) map[string]any {
		t.Helper()
		readiness, _ := payload["readiness"].(map[string]any)
		if readiness == nil {
			t.Fatalf("readiness missing payload=%v", payload)
		}
		return readiness
	}
	getEndpointPosture := func(t *testing.T, readiness map[string]any) map[string]any {
		t.Helper()
		posture, _ := readiness["endpoint_posture"].(map[string]any)
		if posture == nil {
			t.Fatalf("endpoint_posture missing readiness=%v", readiness)
		}
		return posture
	}
	getEndpointWarnings := func(t *testing.T, readiness map[string]any) []string {
		t.Helper()
		rawWarnings, _ := readiness["endpoint_warnings"].([]any)
		out := make([]string, 0, len(rawWarnings))
		for _, raw := range rawWarnings {
			if message, ok := raw.(string); ok && strings.TrimSpace(message) != "" {
				out = append(out, message)
			}
		}
		return out
	}
	mustContainWarning := func(t *testing.T, warnings []string, needle string) {
		t.Helper()
		for _, warning := range warnings {
			if strings.Contains(warning, needle) {
				return
			}
		}
		t.Fatalf("missing warning containing %q warnings=%v", needle, warnings)
	}
	mustFloatField := func(t *testing.T, posture map[string]any, key string, want int) {
		t.Helper()
		gotRaw, ok := posture[key].(float64)
		if !ok {
			t.Fatalf("%s type=%T want float64 posture=%v", key, posture[key], posture)
		}
		if int(gotRaw) != want {
			t.Fatalf("%s=%d want=%d posture=%v", key, int(gotRaw), want, posture)
		}
	}
	now := time.Now().UTC()
	putServerStatusClientSession := func(svc *Service, token, wallet string) {
		svc.gpmState.putSession(gpmSession{
			Token:          token,
			WalletAddress:  wallet,
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})
	}

	t.Run("admin unlocked", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-server-admin-token",
			WalletAddress:  "cosmos1serveradmin",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})

		body := `{"session_token":"gpm-server-admin-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["role"].(string); got != "admin" {
			t.Fatalf("role=%q want=admin payload=%v", got, payload)
		}
		if got, _ := readiness["session_present"].(bool); !got {
			t.Fatalf("session_present=%v want=true payload=%v", readiness["session_present"], payload)
		}
		if got, _ := readiness["tab_visible"].(bool); !got {
			t.Fatalf("tab_visible=%v want=true payload=%v", readiness["tab_visible"], payload)
		}
		if got, _ := readiness["client_tab_visible"].(bool); got {
			t.Fatalf("client_tab_visible=%v want=false payload=%v", readiness["client_tab_visible"], payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); !got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=true payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["service_mutations_configured"].(bool); !got {
			t.Fatalf("service_mutations_configured=%v want=true payload=%v", readiness["service_mutations_configured"], payload)
		}
		clientLockReason, _ := readiness["client_lock_reason"].(string)
		if !strings.Contains(clientLockReason, "client registration is required") {
			t.Fatalf("client_lock_reason=%q want client-registration gate payload=%v", clientLockReason, payload)
		}
	})

	t.Run("admin dual-role keeps client tab visible", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:              "gpm-server-admin-dual-role-token",
			WalletAddress:      "cosmos1serveradmindualrole",
			WalletProvider:     "keplr",
			Role:               "admin",
			CreatedAt:          now,
			ExpiresAt:          now.Add(time.Hour),
			BootstrapDirectory: "https://bootstrap.globalprivatemesh.net",
			InviteKey:          "inv-REDACTED-test-fixture",
		})

		body := `{"session_token":"gpm-server-admin-dual-role-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["client_tab_visible"].(bool); !got {
			t.Fatalf("client_tab_visible=%v want=true payload=%v", readiness["client_tab_visible"], payload)
		}
		if got, _ := readiness["client_lock_reason"].(string); got != "" {
			t.Fatalf("client_lock_reason=%q want empty payload=%v", got, payload)
		}
	})

	t.Run("operator pending locked", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-server-operator-pending-token",
			WalletAddress:   "cosmos1operatorpendingstatus",
			WalletProvider:  "keplr",
			Role:            "operator",
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Hour),
			ChainOperatorID: "operator-pending-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatorpendingstatus",
			ChainOperatorID: "operator-pending-1",
			Status:          "pending",
			UpdatedAt:       now,
		})

		body := `{"session_token":"gpm-server-operator-pending-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["operator_application_status"].(string); got != "pending" {
			t.Fatalf("operator_application_status=%q want=pending payload=%v", got, payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got != "pending_approval" {
			t.Fatalf("chain_binding_status=%q want=pending_approval payload=%v", got, payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); got {
			t.Fatalf("chain_binding_ok=%v want=false payload=%v", readiness["chain_binding_ok"], payload)
		}
		if got, _ := readiness["tab_visible"].(bool); !got {
			t.Fatalf("tab_visible=%v want=true payload=%v", readiness["tab_visible"], payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if !strings.Contains(lockReason, "pending") {
			t.Fatalf("lock_reason=%q want pending message payload=%v", lockReason, payload)
		}
	})

	t.Run("operator approved unlocked", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-server-operator-approved-token",
			WalletAddress:   "cosmos1operatorapprovedstatus",
			WalletProvider:  "keplr",
			Role:            "operator",
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Hour),
			ChainOperatorID: "operator-approved-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatorapprovedstatus",
			ChainOperatorID: "operator-approved-1",
			Status:          "approved",
			UpdatedAt:       now,
		})

		body := `{"session_token":"gpm-server-operator-approved-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["operator_application_status"].(string); got != "approved" {
			t.Fatalf("operator_application_status=%q want=approved payload=%v", got, payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); !got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=true payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got != "bound" {
			t.Fatalf("chain_binding_status=%q want=bound payload=%v", got, payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); !got {
			t.Fatalf("chain_binding_ok=%v want=true payload=%v", readiness["chain_binding_ok"], payload)
		}
		if got, _ := readiness["chain_binding_reason"].(string); got != "" {
			t.Fatalf("chain_binding_reason=%q want empty payload=%v", got, payload)
		}
		if got, _ := readiness["chain_operator_id"].(string); got != "operator-approved-1" {
			t.Fatalf("chain_operator_id=%q want=operator-approved-1 payload=%v", got, payload)
		}
		if got, _ := readiness["session_chain_operator_id"].(string); got != "operator-approved-1" {
			t.Fatalf("session_chain_operator_id=%q want=operator-approved-1 payload=%v", got, payload)
		}
	})

	t.Run("operator approved but chain mismatch locked", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-server-operator-mismatch-token",
			WalletAddress:   "cosmos1operatormismatchstatus",
			WalletProvider:  "keplr",
			Role:            "operator",
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Hour),
			ChainOperatorID: "operator-approved-a",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatormismatchstatus",
			ChainOperatorID: "operator-approved-b",
			Status:          "approved",
			UpdatedAt:       now,
		})

		body := `{"session_token":"gpm-server-operator-mismatch-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got != "mismatch" {
			t.Fatalf("chain_binding_status=%q want=mismatch payload=%v", got, payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); got {
			t.Fatalf("chain_binding_ok=%v want=false payload=%v", readiness["chain_binding_ok"], payload)
		}
		chainBindingReason, _ := readiness["chain_binding_reason"].(string)
		if !strings.Contains(chainBindingReason, "does not match") {
			t.Fatalf("chain_binding_reason=%q want mismatch message payload=%v", chainBindingReason, payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if !strings.Contains(lockReason, "out of sync") && !strings.Contains(lockReason, "does not match") {
			t.Fatalf("lock_reason=%q want out-of-sync or mismatch message payload=%v", lockReason, payload)
		}
	})

	t.Run("operator approved but missing session chain operator id locked", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-server-operator-missing-session-chain-token",
			WalletAddress:  "cosmos1operatormissingsessionchainstatus",
			WalletProvider: "keplr",
			Role:           "operator",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatormissingsessionchainstatus",
			ChainOperatorID: "operator-approved-missing-session-chain-status-1",
			Status:          "approved",
			UpdatedAt:       now,
		})

		body := `{"session_token":"gpm-server-operator-missing-session-chain-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["operator_application_status"].(string); got != "approved" {
			t.Fatalf("operator_application_status=%q want=approved payload=%v", got, payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); got {
			t.Fatalf("chain_binding_ok=%v want=false payload=%v", readiness["chain_binding_ok"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got == "bound" {
			t.Fatalf("chain_binding_status=%q want non-bound payload=%v", got, payload)
		}
		chainBindingReason, _ := readiness["chain_binding_reason"].(string)
		if strings.TrimSpace(chainBindingReason) == "" {
			t.Fatalf("chain_binding_reason=%q want non-empty payload=%v", chainBindingReason, payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if strings.TrimSpace(lockReason) == "" {
			t.Fatalf("lock_reason=%q want non-empty payload=%v", lockReason, payload)
		}
	})

	t.Run("operator approved but missing approved chain operator id locked", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-server-operator-missing-approved-chain-token",
			WalletAddress:   "cosmos1operatormissingapprovedchainstatus",
			WalletProvider:  "keplr",
			Role:            "operator",
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Hour),
			ChainOperatorID: "operator-approved-missing-approved-chain-status-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress: "cosmos1operatormissingapprovedchainstatus",
			Status:        "approved",
			UpdatedAt:     now,
		})

		body := `{"session_token":"gpm-server-operator-missing-approved-chain-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["operator_application_status"].(string); got != "approved" {
			t.Fatalf("operator_application_status=%q want=approved payload=%v", got, payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); got {
			t.Fatalf("chain_binding_ok=%v want=false payload=%v", readiness["chain_binding_ok"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got == "bound" {
			t.Fatalf("chain_binding_status=%q want non-bound payload=%v", got, payload)
		}
		chainBindingReason, _ := readiness["chain_binding_reason"].(string)
		if strings.TrimSpace(chainBindingReason) == "" {
			t.Fatalf("chain_binding_reason=%q want non-empty payload=%v", chainBindingReason, payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if strings.TrimSpace(lockReason) == "" {
			t.Fatalf("lock_reason=%q want non-empty payload=%v", lockReason, payload)
		}
	})

	t.Run("client role locked and tab hidden", func(t *testing.T) {
		svc := newServerStatusService(t)
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-server-client-token",
			WalletAddress:  "cosmos1clientstatus",
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})

		body := `{"session_token":"gpm-server-client-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["role"].(string); got != "client" {
			t.Fatalf("role=%q want=client payload=%v", got, payload)
		}
		if got, _ := readiness["tab_visible"].(bool); got {
			t.Fatalf("tab_visible=%v want=false payload=%v", readiness["tab_visible"], payload)
		}
		if got, _ := readiness["client_tab_visible"].(bool); !got {
			t.Fatalf("client_tab_visible=%v want=true payload=%v", readiness["client_tab_visible"], payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got != "not_applicable" {
			t.Fatalf("chain_binding_status=%q want=not_applicable payload=%v", got, payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); got {
			t.Fatalf("chain_binding_ok=%v want=false payload=%v", readiness["chain_binding_ok"], payload)
		}
		if got, _ := readiness["chain_binding_reason"].(string); got != "" {
			t.Fatalf("chain_binding_reason=%q want empty payload=%v", got, payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if !strings.Contains(lockReason, "operator or admin required") {
			t.Fatalf("lock_reason=%q want operator/admin gate payload=%v", lockReason, payload)
		}
		if got, _ := readiness["client_lock_reason"].(string); got != "" {
			t.Fatalf("client_lock_reason=%q want empty payload=%v", got, payload)
		}
	})

	t.Run("wallet-only path with not_submitted", func(t *testing.T) {
		svc := newServerStatusService(t)
		putServerStatusClientSession(svc, "gpm-server-wallet-only-status-token", "cosmos1walletonlystatus")

		body := `{"session_token":"gpm-server-wallet-only-status-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["wallet_address"].(string); got != "cosmos1walletonlystatus" {
			t.Fatalf("wallet_address=%q want=cosmos1walletonlystatus payload=%v", got, payload)
		}
		if got, _ := readiness["session_present"].(bool); !got {
			t.Fatalf("session_present=%v want=true payload=%v", readiness["session_present"], payload)
		}
		if got, _ := readiness["operator_application_status"].(string); got != "not_submitted" {
			t.Fatalf("operator_application_status=%q want=not_submitted payload=%v", got, payload)
		}
		if got, _ := readiness["role"].(string); got != "client" {
			t.Fatalf("role=%q want=client payload=%v", got, payload)
		}
	})

	t.Run("endpoint diagnostics are additive and backward compatible", func(t *testing.T) {
		svc := newServerStatusService(t)
		putServerStatusClientSession(svc, "gpm-server-diag-backcompat-token", "cosmos1diagbackcompat")
		t.Setenv("EASY_NODE_SERVER_MODE", "")
		t.Setenv("CORE_ISSUER_URL", "")
		t.Setenv("ISSUER_URLS", "")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "")

		body := `{"session_token":"gpm-server-diag-backcompat-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["operator_application_status"].(string); got != "not_submitted" {
			t.Fatalf("operator_application_status=%q want=not_submitted payload=%v", got, payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if !strings.Contains(lockReason, "operator or admin required") {
			t.Fatalf("lock_reason=%q want operator/admin gate payload=%v", lockReason, payload)
		}
		posture := getEndpointPosture(t, readiness)
		if got, _ := posture["server_mode"].(string); got != "" {
			t.Fatalf("server_mode=%q want empty posture=%v", got, posture)
		}
		mustFloatField(t, posture, "total_urls", 0)
		mustFloatField(t, posture, "http_urls", 0)
		mustFloatField(t, posture, "https_urls", 0)
		if got, _ := posture["mixed_scheme"].(bool); got {
			t.Fatalf("mixed_scheme=%v want=false posture=%v", got, posture)
		}
		if got, _ := posture["has_remote_http"].(bool); got {
			t.Fatalf("has_remote_http=%v want=false posture=%v", got, posture)
		}
		warnings := getEndpointWarnings(t, readiness)
		if len(warnings) != 0 {
			t.Fatalf("endpoint_warnings=%v want empty", warnings)
		}
	})

	t.Run("provider mode missing issuer configuration warns", func(t *testing.T) {
		svc := newServerStatusService(t)
		putServerStatusClientSession(svc, "gpm-server-diag-provider-token", "cosmos1diagprovider")
		t.Setenv("EASY_NODE_SERVER_MODE", "provider")
		t.Setenv("CORE_ISSUER_URL", "")
		t.Setenv("ISSUER_URLS", "")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "")

		body := `{"session_token":"gpm-server-diag-provider-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		posture := getEndpointPosture(t, readiness)
		if got, _ := posture["server_mode"].(string); got != "provider" {
			t.Fatalf("server_mode=%q want=provider posture=%v", got, posture)
		}
		warnings := getEndpointWarnings(t, readiness)
		mustContainWarning(t, warnings, "provider mode requires CORE_ISSUER_URL")
		mustContainWarning(t, warnings, "provider mode requires ISSUER_URLS")
	})

	t.Run("authority mode missing trust configuration warns", func(t *testing.T) {
		svc := newServerStatusService(t)
		putServerStatusClientSession(svc, "gpm-server-diag-authority-token", "cosmos1diagauthority")
		t.Setenv("EASY_NODE_SERVER_MODE", "authority")
		t.Setenv("CORE_ISSUER_URL", "https://authority.globalprivatemesh.example:8082")
		t.Setenv("ISSUER_URLS", "")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "")

		body := `{"session_token":"gpm-server-diag-authority-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		posture := getEndpointPosture(t, readiness)
		if got, _ := posture["server_mode"].(string); got != "authority" {
			t.Fatalf("server_mode=%q want=authority posture=%v", got, posture)
		}
		warnings := getEndpointWarnings(t, readiness)
		mustContainWarning(t, warnings, "authority mode requires ISSUER_URLS")
		mustContainWarning(t, warnings, "authority mode requires DIRECTORY_ISSUER_TRUST_URLS")
	})

	t.Run("mixed scheme remote http and core mismatch warnings", func(t *testing.T) {
		svc := newServerStatusService(t)
		putServerStatusClientSession(svc, "gpm-server-diag-mixed-token", "cosmos1diagmixed")
		t.Setenv("EASY_NODE_SERVER_MODE", "provider")
		t.Setenv("CORE_ISSUER_URL", "https://core.globalprivatemesh.example:8082")
		t.Setenv("ISSUER_URLS", "https://issuer-a.globalprivatemesh.example:8082,http://203.0.113.20:8082")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "https://issuer-b.globalprivatemesh.example:8082,http://198.51.100.21:8082")

		body := `{"session_token":"gpm-server-diag-mixed-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		posture := getEndpointPosture(t, readiness)
		mustFloatField(t, posture, "total_urls", 5)
		mustFloatField(t, posture, "http_urls", 2)
		mustFloatField(t, posture, "https_urls", 3)
		if got, _ := posture["mixed_scheme"].(bool); !got {
			t.Fatalf("mixed_scheme=%v want=true posture=%v", got, posture)
		}
		if got, _ := posture["has_remote_http"].(bool); !got {
			t.Fatalf("has_remote_http=%v want=true posture=%v", got, posture)
		}
		warnings := getEndpointWarnings(t, readiness)
		mustContainWarning(t, warnings, "CORE_ISSUER_URL is not present in ISSUER_URLS")
		mustContainWarning(t, warnings, "CORE_ISSUER_URL is not present in DIRECTORY_ISSUER_TRUST_URLS")
		mustContainWarning(t, warnings, "mixed HTTP/HTTPS endpoint posture detected")
		mustContainWarning(t, warnings, "remote HTTP endpoint detected")
	})

	t.Run("explicit invalid session token returns 404", func(t *testing.T) {
		svc := newServerStatusService(t)

		body := `{"session_token":"gpm-server-status-missing-token","wallet_address":"cosmos1walletprovided"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusNotFound {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session not found") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})
}

func TestGPMOnboardingOverview(t *testing.T) {
	newOverviewService := func(t *testing.T) *Service {
		t.Helper()
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = lifecycleSuccessCommand("start")
		svc.serviceStop = lifecycleSuccessCommand("stop")
		svc.serviceRestart = lifecycleSuccessCommand("restart")
		return svc
	}

	now := time.Now().UTC()

	t.Run("method not allowed", func(t *testing.T) {
		svc := newOverviewService(t)
		code, payload := callJSONHandler(t, svc.handleGPMOnboardingOverview, http.MethodGet, "/v1/gpm/onboarding/overview", "")
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "method not allowed") {
			t.Fatalf("error=%q payload=%v", got, payload)
		}
	})

	t.Run("missing session token", func(t *testing.T) {
		svc := newOverviewService(t)
		code, payload := callJSONHandler(t, svc.handleGPMOnboardingOverview, http.MethodPost, "/v1/gpm/onboarding/overview", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session_token is required") {
			t.Fatalf("error=%q payload=%v", got, payload)
		}
	})

	t.Run("invalid session", func(t *testing.T) {
		svc := newOverviewService(t)
		code, payload := callJSONHandler(t, svc.handleGPMOnboardingOverview, http.MethodPost, "/v1/gpm/onboarding/overview", `{"session_token":"gpm-overview-missing"}`)
		if code != http.StatusNotFound {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "session not found") {
			t.Fatalf("error=%q payload=%v", got, payload)
		}
	})

	t.Run("happy path returns session registration and readiness", func(t *testing.T) {
		svc := newOverviewService(t)
		const (
			sessionToken = "gpm-overview-operator-approved-token"
			wallet       = "cosmos1overviewapproved"
			chainID      = "operator-overview-1"
			bootstrapDir = "https://directory.globalprivatemesh.example:8081"
		)
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": []string{bootstrapDir},
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL
		svc.gpmState.putSession(gpmSession{
			Token:              sessionToken,
			WalletAddress:      wallet,
			WalletProvider:     "keplr",
			Role:               "operator",
			CreatedAt:          now,
			ExpiresAt:          now.Add(time.Hour),
			BootstrapDirectory: bootstrapDir,
			InviteKey:          "inv-overview-approved",
			PathProfile:        "3hop",
			ChainOperatorID:    chainID,
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   wallet,
			ChainOperatorID: chainID,
			Status:          "approved",
			UpdatedAt:       now,
		})

		code, payload := callJSONHandler(
			t,
			svc.handleGPMOnboardingOverview,
			http.MethodPost,
			"/v1/gpm/onboarding/overview",
			`{"session_token":"`+sessionToken+`"}`,
		)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if ok, _ := payload["ok"].(bool); !ok {
			t.Fatalf("ok=%v payload=%v", payload["ok"], payload)
		}

		sessionPayload, _ := payload["session"].(map[string]any)
		if sessionPayload == nil {
			t.Fatalf("session missing payload=%v", payload)
		}
		if got, _ := sessionPayload["wallet_address"].(string); got != wallet {
			t.Fatalf("session.wallet_address=%q want=%q payload=%v", got, wallet, payload)
		}

		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		if got, _ := registration["status"].(string); got != "registered" {
			t.Fatalf("registration.status=%q want=registered payload=%v", got, payload)
		}
		if got, _ := registration["wallet_address"].(string); got != wallet {
			t.Fatalf("registration.wallet_address=%q want=%q payload=%v", got, wallet, payload)
		}

		readiness, _ := payload["readiness"].(map[string]any)
		if readiness == nil {
			t.Fatalf("readiness missing payload=%v", payload)
		}
		if got, _ := readiness["role"].(string); got != "operator" {
			t.Fatalf("readiness.role=%q want=operator payload=%v", got, payload)
		}
		if got, _ := readiness["operator_application_status"].(string); got != "approved" {
			t.Fatalf("readiness.operator_application_status=%q want=approved payload=%v", got, payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); !got {
			t.Fatalf("readiness.lifecycle_actions_unlocked=%v want=true payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got != "bound" {
			t.Fatalf("readiness.chain_binding_status=%q want=bound payload=%v", got, payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); !got {
			t.Fatalf("readiness.chain_binding_ok=%v want=true payload=%v", readiness["chain_binding_ok"], payload)
		}
		if _, ok := readiness["chain_binding_reason"]; !ok {
			t.Fatalf("readiness.chain_binding_reason missing payload=%v", payload)
		}
	})

	t.Run("manifest drift revokes registration readiness", func(t *testing.T) {
		svc := newOverviewService(t)
		const (
			sessionToken = "gpm-overview-registration-drift-token"
			wallet       = "cosmos1overviewregistrationdrift"
			chainID      = "operator-overview-registration-drift-1"
		)
		manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":               1,
				"generated_at_utc":      now.Format(time.RFC3339),
				"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
				"bootstrap_directories": []string{"https://directory.current-trusted.globalprivatemesh.example:8081"},
			})
		}))
		t.Cleanup(manifestServer.Close)
		svc.gpmMainDomain = manifestServer.URL
		svc.gpmManifestURL = manifestServer.URL
		svc.gpmState.putSession(gpmSession{
			Token:                sessionToken,
			WalletAddress:        wallet,
			WalletProvider:       "keplr",
			Role:                 "operator",
			CreatedAt:            now,
			ExpiresAt:            now.Add(time.Hour),
			BootstrapDirectory:   "https://directory.revoked.globalprivatemesh.example:8081",
			BootstrapDirectories: []string{"https://directory.revoked.globalprivatemesh.example:8081"},
			InviteKey:            "inv-overview-drifted",
			PathProfile:          "2hop",
			ChainOperatorID:      chainID,
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   wallet,
			ChainOperatorID: chainID,
			Status:          "approved",
			UpdatedAt:       now,
		})

		code, payload := callJSONHandler(
			t,
			svc.handleGPMOnboardingOverview,
			http.MethodPost,
			"/v1/gpm/onboarding/overview",
			`{"session_token":"`+sessionToken+`"}`,
		)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		if got, _ := registration["status"].(string); got != "not_registered" {
			t.Fatalf("registration.status=%q want=not_registered payload=%v", got, payload)
		}
		if got, _ := registration["status_reason"].(string); !strings.Contains(got, "no longer trusted") {
			t.Fatalf("registration.status_reason=%q want trust-revoked guidance payload=%v", got, payload)
		}
		readiness, _ := payload["readiness"].(map[string]any)
		if readiness == nil {
			t.Fatalf("readiness missing payload=%v", payload)
		}
		if got, _ := readiness["client_registration_status"].(string); got != "not_registered" {
			t.Fatalf("readiness.client_registration_status=%q want=not_registered payload=%v", got, payload)
		}
		if got, _ := readiness["client_tab_visible"].(bool); got {
			t.Fatalf("readiness.client_tab_visible=%v want=false payload=%v", readiness["client_tab_visible"], payload)
		}
		if got, _ := readiness["client_lock_reason"].(string); !strings.Contains(got, "no longer trusted") {
			t.Fatalf("readiness.client_lock_reason=%q want trust-revoked guidance payload=%v", got, payload)
		}
	})

	t.Run("manifest revalidation hard failure reports degraded registration readiness", func(t *testing.T) {
		svc := newOverviewService(t)
		const sessionToken = "gpm-overview-registration-degraded-token"
		svc.gpmState.putSession(gpmSession{
			Token:                sessionToken,
			WalletAddress:        "cosmos1overviewregistrationdegraded",
			WalletProvider:       "keplr",
			Role:                 "admin",
			CreatedAt:            now,
			ExpiresAt:            now.Add(time.Hour),
			BootstrapDirectory:   "https://directory.globalprivatemesh.example:8081",
			BootstrapDirectories: []string{"https://directory.globalprivatemesh.example:8081"},
			InviteKey:            "inv-overview-degraded",
			PathProfile:          "2hop",
		})

		code, payload := callJSONHandler(
			t,
			svc.handleGPMOnboardingOverview,
			http.MethodPost,
			"/v1/gpm/onboarding/overview",
			`{"session_token":"`+sessionToken+`"}`,
		)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		if got, _ := registration["status"].(string); got != "degraded" {
			t.Fatalf("registration.status=%q want=degraded payload=%v", got, payload)
		}
		if got, _ := registration["status_reason"].(string); !strings.Contains(got, "failed to revalidate") {
			t.Fatalf("registration.status_reason=%q want hard-failure guidance payload=%v", got, payload)
		}
		readiness, _ := payload["readiness"].(map[string]any)
		if readiness == nil {
			t.Fatalf("readiness missing payload=%v", payload)
		}
		if got, _ := readiness["client_registration_status"].(string); got != "degraded" {
			t.Fatalf("readiness.client_registration_status=%q want=degraded payload=%v", got, payload)
		}
		if got, _ := readiness["client_tab_visible"].(bool); got {
			t.Fatalf("readiness.client_tab_visible=%v want=false payload=%v", readiness["client_tab_visible"], payload)
		}
		if got, _ := readiness["client_lock_reason"].(string); !strings.Contains(got, "failed to revalidate") {
			t.Fatalf("readiness.client_lock_reason=%q want hard-failure guidance payload=%v", got, payload)
		}
	})

	t.Run("approved operator with missing session chain operator id reports locked non-bound readiness", func(t *testing.T) {
		svc := newOverviewService(t)
		const (
			sessionToken = "gpm-overview-operator-approved-missing-session-chain-token"
			wallet       = "cosmos1overviewmissingchainsession"
		)
		svc.gpmState.putSession(gpmSession{
			Token:              sessionToken,
			WalletAddress:      wallet,
			WalletProvider:     "keplr",
			Role:               "operator",
			CreatedAt:          now,
			ExpiresAt:          now.Add(time.Hour),
			BootstrapDirectory: "https://directory.globalprivatemesh.example:8081",
			InviteKey:          "inv-overview-missing-session-chain",
			PathProfile:        "2hop",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   wallet,
			ChainOperatorID: "operator-overview-missing-session-chain-1",
			Status:          "approved",
			UpdatedAt:       now,
		})

		code, payload := callJSONHandler(
			t,
			svc.handleGPMOnboardingOverview,
			http.MethodPost,
			"/v1/gpm/onboarding/overview",
			`{"session_token":"`+sessionToken+`"}`,
		)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}

		readiness, _ := payload["readiness"].(map[string]any)
		if readiness == nil {
			t.Fatalf("readiness missing payload=%v", payload)
		}
		if got, _ := readiness["operator_application_status"].(string); got != "approved" {
			t.Fatalf("readiness.operator_application_status=%q want=approved payload=%v", got, payload)
		}
		if got, _ := readiness["lifecycle_actions_unlocked"].(bool); got {
			t.Fatalf("readiness.lifecycle_actions_unlocked=%v want=false payload=%v", readiness["lifecycle_actions_unlocked"], payload)
		}
		if got, _ := readiness["chain_binding_ok"].(bool); got {
			t.Fatalf("readiness.chain_binding_ok=%v want=false payload=%v", readiness["chain_binding_ok"], payload)
		}
		if got, _ := readiness["chain_binding_status"].(string); got == "bound" {
			t.Fatalf("readiness.chain_binding_status=%q want non-bound payload=%v", got, payload)
		}
		chainBindingReason, _ := readiness["chain_binding_reason"].(string)
		if strings.TrimSpace(chainBindingReason) == "" {
			t.Fatalf("readiness.chain_binding_reason=%q want non-empty payload=%v", chainBindingReason, payload)
		}
		lockReason, _ := readiness["lock_reason"].(string)
		if strings.TrimSpace(lockReason) == "" {
			t.Fatalf("readiness.lock_reason=%q want non-empty payload=%v", lockReason, payload)
		}
	})
}

func TestGPMOperatorList(t *testing.T) {
	newOperatorListService := func(t *testing.T) *Service {
		t.Helper()
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		return svc
	}
	putAdminSession := func(svc *Service, token string, now time.Time) {
		svc.gpmState.putSession(gpmSession{
			Token:                  token,
			WalletAddress:          "cosmos1operatorlistadmin",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              now,
			ExpiresAt:              now.Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1operatorlistadmin")
	}

	t.Run("missing session token", func(t *testing.T) {
		svc := newOperatorListService(t)
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session_token is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("invalid session", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-expired-list-token",
			WalletAddress:  "cosmos1expiredlist",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      now.Add(-2 * time.Hour),
			ExpiresAt:      now.Add(-time.Minute),
		})
		body := `{"session_token":"gpm-expired-list-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusNotFound {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session not found") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("non-admin session", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-client-list-token",
			WalletAddress:  "cosmos1clientlist",
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})
		body := `{"session_token":"gpm-client-list-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "admin session role is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("admin list returns sorted items", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-sorted-token", now)
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1sortb",
			ChainOperatorID: "operator-sort-b",
			Status:          "approved",
			UpdatedAt:       now,
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1sorta",
			ChainOperatorID: "operator-sort-a",
			Status:          "pending",
			UpdatedAt:       now,
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1sortc",
			ChainOperatorID: "operator-sort-c",
			Status:          "rejected",
			UpdatedAt:       now.Add(-time.Minute),
		})

		body := `{"session_token":"gpm-admin-list-sorted-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if count, _ := payload["count"].(float64); int(count) != 3 {
			t.Fatalf("count=%v want=3 payload=%v", count, payload)
		}
		applications, _ := payload["applications"].([]any)
		if len(applications) != 3 {
			t.Fatalf("applications len=%d want=3 payload=%v", len(applications), payload)
		}
		walletAt := func(idx int) string {
			app, _ := applications[idx].(map[string]any)
			wallet, _ := app["wallet_address"].(string)
			return wallet
		}
		if got := walletAt(0); got != "cosmos1sorta" {
			t.Fatalf("applications[0].wallet_address=%q want=cosmos1sorta payload=%v", got, payload)
		}
		if got := walletAt(1); got != "cosmos1sortb" {
			t.Fatalf("applications[1].wallet_address=%q want=cosmos1sortb payload=%v", got, payload)
		}
		if got := walletAt(2); got != "cosmos1sortc" {
			t.Fatalf("applications[2].wallet_address=%q want=cosmos1sortc payload=%v", got, payload)
		}
	})

	t.Run("admin status filter works", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-filter-token", now)
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1approvedone",
			ChainOperatorID: "operator-approved-one",
			Status:          "approved",
			UpdatedAt:       now,
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1pendingone",
			ChainOperatorID: "operator-pending-one",
			Status:          "pending",
			UpdatedAt:       now.Add(-time.Minute),
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1approvedtwo",
			ChainOperatorID: "operator-approved-two",
			Status:          "approved",
			UpdatedAt:       now.Add(-2 * time.Minute),
		})

		body := `{"session_token":"gpm-admin-list-filter-token","status":"approved"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if count, _ := payload["count"].(float64); int(count) != 2 {
			t.Fatalf("count=%v want=2 payload=%v", count, payload)
		}
		applications, _ := payload["applications"].([]any)
		if len(applications) != 2 {
			t.Fatalf("applications len=%d want=2 payload=%v", len(applications), payload)
		}
		for idx, raw := range applications {
			app, _ := raw.(map[string]any)
			if got, _ := app["status"].(string); got != "approved" {
				t.Fatalf("applications[%d].status=%q want=approved payload=%v", idx, got, payload)
			}
		}
	})

	t.Run("limit clamp works", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-limit-token", now)
		for i := 0; i < 520; i++ {
			svc.gpmState.upsertOperator(gpmOperatorApplication{
				WalletAddress:   "cosmos1limit" + strconv.Itoa(i),
				ChainOperatorID: "operator-limit-" + strconv.Itoa(i),
				Status:          "pending",
				UpdatedAt:       now.Add(-time.Duration(i) * time.Second),
			})
		}

		body := `{"session_token":"gpm-admin-list-limit-token","limit":9999}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if count, _ := payload["count"].(float64); int(count) != 500 {
			t.Fatalf("count=%v want=500 payload=%v", count, payload)
		}
		applications, _ := payload["applications"].([]any)
		if len(applications) != 500 {
			t.Fatalf("applications len=%d want=500 payload=%v", len(applications), payload)
		}

		body = `{"session_token":"gpm-admin-list-limit-token","limit":0}`
		code, payload = callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if count, _ := payload["count"].(float64); int(count) != 1 {
			t.Fatalf("count=%v want=1 payload=%v", count, payload)
		}
		applications, _ = payload["applications"].([]any)
		if len(applications) != 1 {
			t.Fatalf("applications len=%d want=1 payload=%v", len(applications), payload)
		}
	})

	t.Run("invalid status filter", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-invalid-status-token", now)
		body := `{"session_token":"gpm-admin-list-invalid-status-token","status":"paused"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "status must be one of") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("search filter works across wallet and chain operator id", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-search-token", now)
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1searchalpha",
			ChainOperatorID: "operator-search-alpha",
			Status:          "pending",
			UpdatedAt:       now,
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1searchbeta",
			ChainOperatorID: "operator-target-beta",
			Status:          "approved",
			UpdatedAt:       now.Add(-time.Minute),
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1other",
			ChainOperatorID: "operator-other",
			Status:          "pending",
			UpdatedAt:       now.Add(-2 * time.Minute),
		})

		body := `{"session_token":"gpm-admin-list-search-token","search":"target-beta","limit":10}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if count, _ := payload["count"].(float64); int(count) != 1 {
			t.Fatalf("count=%v want=1 payload=%v", count, payload)
		}
		applications, _ := payload["applications"].([]any)
		if len(applications) != 1 {
			t.Fatalf("applications len=%d want=1 payload=%v", len(applications), payload)
		}
		first, _ := applications[0].(map[string]any)
		if got, _ := first["wallet_address"].(string); got != "cosmos1searchbeta" {
			t.Fatalf("wallet_address=%q want=cosmos1searchbeta payload=%v", got, payload)
		}
	})

	t.Run("cursor pagination returns next page and cursor metadata", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-cursor-token", now)

		entries := []gpmOperatorApplication{
			{
				WalletAddress:   "cosmos1cursorone",
				ChainOperatorID: "operator-cursor-one",
				Status:          "pending",
				UpdatedAt:       now,
			},
			{
				WalletAddress:   "cosmos1cursortwo",
				ChainOperatorID: "operator-cursor-two",
				Status:          "pending",
				UpdatedAt:       now.Add(-time.Minute),
			},
			{
				WalletAddress:   "cosmos1cursorthree",
				ChainOperatorID: "operator-cursor-three",
				Status:          "pending",
				UpdatedAt:       now.Add(-2 * time.Minute),
			},
		}
		for _, entry := range entries {
			svc.gpmState.upsertOperator(entry)
		}

		firstBody := `{"session_token":"gpm-admin-list-cursor-token","status":"pending","limit":2}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", firstBody)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if hasMore, _ := payload["has_more"].(bool); !hasMore {
			t.Fatalf("has_more=%v want=true payload=%v", payload["has_more"], payload)
		}
		nextCursor, _ := payload["next_cursor"].(string)
		if strings.TrimSpace(nextCursor) == "" {
			t.Fatalf("next_cursor=%q want non-empty payload=%v", nextCursor, payload)
		}
		applications, _ := payload["applications"].([]any)
		if len(applications) != 2 {
			t.Fatalf("applications len=%d want=2 payload=%v", len(applications), payload)
		}

		secondBody := fmt.Sprintf(`{"session_token":"gpm-admin-list-cursor-token","status":"pending","limit":2,"cursor":%q}`, nextCursor)
		code, payload = callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", secondBody)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if hasMore, _ := payload["has_more"].(bool); hasMore {
			t.Fatalf("has_more=%v want=false payload=%v", payload["has_more"], payload)
		}
		applications, _ = payload["applications"].([]any)
		if len(applications) != 1 {
			t.Fatalf("applications len=%d want=1 payload=%v", len(applications), payload)
		}
		first, _ := applications[0].(map[string]any)
		if got, _ := first["wallet_address"].(string); got != "cosmos1cursorthree" {
			t.Fatalf("wallet_address=%q want=cosmos1cursorthree payload=%v", got, payload)
		}
	})

	t.Run("invalid cursor format returns 400", func(t *testing.T) {
		svc := newOperatorListService(t)
		now := time.Now().UTC()
		putAdminSession(svc, "gpm-admin-list-invalid-cursor-token", now)
		body := `{"session_token":"gpm-admin-list-invalid-cursor-token","cursor":"invalid-cursor"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorList, http.MethodPost, "/v1/gpm/onboarding/operator/list", body)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "cursor must be in the format") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})
}

func TestGPMOperatorApproveAuthorization(t *testing.T) {
	newOperatorApproveService := func(t *testing.T) *Service {
		t.Helper()
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1approvaltarget",
			ChainOperatorID: "operator-approval-target",
			Status:          "pending",
			UpdatedAt:       time.Now().UTC(),
		})
		return svc
	}

	t.Run("requires admin session when approval token is unset", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "admin session_token is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("rejects non-admin session token", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-client-approval-token",
			WalletAddress:  "cosmos1clientapprover",
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      time.Now().UTC(),
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		})
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"session_token":"gpm-client-approval-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "admin session role is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("approves with admin session token", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmState.putSession(gpmSession{
			Token:                  "gpm-admin-approval-token",
			WalletAddress:          "cosmos1adminapprover",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              time.Now().UTC(),
			ExpiresAt:              time.Now().UTC().Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1adminapprover")
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"session_token":"gpm-admin-approval-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "approved" {
			t.Fatalf("decision=%q want=approved payload=%v", got, payload)
		}
		if got, _ := payload["decision_auth"].(string); got != "admin_session" {
			t.Fatalf("decision_auth=%q want=admin_session payload=%v", got, payload)
		}
		application, _ := payload["application"].(map[string]any)
		if got, _ := application["status"].(string); got != "approved" {
			t.Fatalf("application.status=%q want=approved payload=%v", got, payload)
		}
	})

	t.Run("production disables local admin approval decisions", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmConnectPolicyMode = "production"
		svc.gpmState.putSession(gpmSession{
			Token:                  "gpm-admin-approval-production-token",
			WalletAddress:          "cosmos1adminapproverprod",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              time.Now().UTC(),
			ExpiresAt:              time.Now().UTC().Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1adminapproverprod")
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"session_token":"gpm-admin-approval-production-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
		}
		if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "chain-governance approval evidence") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
		app, ok := svc.gpmState.getOperator("cosmos1approvaltarget")
		if !ok {
			t.Fatal("expected operator application")
		}
		if got := strings.ToLower(strings.TrimSpace(app.Status)); got != "pending" {
			t.Fatalf("application status=%q want pending", got)
		}
	})

	t.Run("rejects admin session when admin wallet is no longer allowlisted", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmState.putSession(gpmSession{
			Token:                  "gpm-admin-approval-revoked-token",
			WalletAddress:          "cosmos1revokedadminapprover",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              time.Now().UTC(),
			ExpiresAt:              time.Now().UTC().Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1revokedadminapprover")
		delete(svc.gpmAdminWalletAllowlist, "cosmos1revokedadminapprover")

		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"session_token":"gpm-admin-approval-revoked-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "admin wallet is not currently allowlisted") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("legacy admin token fallback still works when configured", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmApprovalToken = "legacy-approval-token"
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"admin_token":"legacy-approval-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "approved" {
			t.Fatalf("decision=%q want=approved payload=%v", got, payload)
		}
		if got, _ := payload["decision_auth"].(string); got != "legacy_admin_token" {
			t.Fatalf("decision_auth=%q want=legacy_admin_token payload=%v", got, payload)
		}
		application, _ := payload["application"].(map[string]any)
		if got, _ := application["status"].(string); got != "approved" {
			t.Fatalf("application.status=%q want=approved payload=%v", got, payload)
		}
	})

	t.Run("strict mode rejects legacy admin token fallback", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmApprovalToken = "legacy-approval-token"
		svc.gpmOperatorApprovalRequireSession = true
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"admin_token":"legacy-approval-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "required by operator approval policy") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
		if !strings.Contains(errMsg, "legacy admin_token fallback is disabled") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("strict mode still approves with admin session token", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmApprovalToken = "legacy-approval-token"
		svc.gpmOperatorApprovalRequireSession = true
		svc.gpmState.putSession(gpmSession{
			Token:                  "gpm-admin-approval-strict-token",
			WalletAddress:          "cosmos1strictadminapprover",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              time.Now().UTC(),
			ExpiresAt:              time.Now().UTC().Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1strictadminapprover")
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"session_token":"gpm-admin-approval-strict-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision_auth"].(string); got != "admin_session" {
			t.Fatalf("decision_auth=%q want=admin_session payload=%v", got, payload)
		}
	})

	t.Run("configured legacy admin token rejects invalid token", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmApprovalToken = "legacy-approval-token"
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"admin_token":"wrong-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "invalid approval admin token") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("rejects unbound admin session token", func(t *testing.T) {
		svc := newOperatorApproveService(t)
		svc.gpmState.putSession(gpmSession{
			Token:          "gpm-admin-approval-unbound-token",
			WalletAddress:  "cosmos1unboundadminapprover",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      time.Now().UTC(),
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		})
		body := `{"wallet_address":"cosmos1approvaltarget","approved":true,"session_token":"gpm-admin-approval-unbound-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "wallet-bound admin session") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})
}

func TestGPMOperatorApproveDecisionContract(t *testing.T) {
	newOperatorApproveDecisionService := func(t *testing.T, chainOperatorID string) *Service {
		t.Helper()
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1approvaldecision",
			ChainOperatorID: chainOperatorID,
			Status:          "pending",
			UpdatedAt:       time.Now().UTC(),
		})
		return svc
	}

	putAdminSession := func(svc *Service, token string) {
		now := time.Now().UTC()
		svc.gpmState.putSession(gpmSession{
			Token:                  token,
			WalletAddress:          "cosmos1decisionadmin",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              now,
			ExpiresAt:              now.Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1decisionadmin")
	}

	t.Run("rejection without reason returns bad request", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "operator-decision-1")
		putAdminSession(svc, "gpm-admin-decision-reject-missing-reason")
		body := `{"wallet_address":"cosmos1approvaldecision","approved":false,"session_token":"gpm-admin-decision-reject-missing-reason"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "reason is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("rejection with reason returns rejected status", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "operator-decision-2")
		putAdminSession(svc, "gpm-admin-decision-reject-reason")
		body := `{"wallet_address":"cosmos1approvaldecision","approved":false,"reason":"duplicate application","session_token":"gpm-admin-decision-reject-reason"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "rejected" {
			t.Fatalf("decision=%q want=rejected payload=%v", got, payload)
		}
		application, _ := payload["application"].(map[string]any)
		if got, _ := application["status"].(string); got != "rejected" {
			t.Fatalf("application.status=%q want=rejected payload=%v", got, payload)
		}
	})

	t.Run("rejection demotes matching operator session to client", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "operator-decision-demote")
		putAdminSession(svc, "gpm-admin-decision-reject-demote")
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-operator-decision-session",
			WalletAddress:   "cosmos1approvaldecision",
			WalletProvider:  "keplr",
			Role:            "operator",
			ChainOperatorID: "operator-decision-demote",
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().UTC().Add(time.Hour),
		})

		body := `{"wallet_address":"cosmos1approvaldecision","approved":false,"reason":"no longer eligible","session_token":"gpm-admin-decision-reject-demote"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "rejected" {
			t.Fatalf("decision=%q want=rejected payload=%v", got, payload)
		}

		session, ok := svc.gpmState.getSession("gpm-operator-decision-session", time.Now().UTC())
		if !ok {
			t.Fatalf("expected session to remain present")
		}
		if session.Role != "client" {
			t.Fatalf("session role=%q want=client", session.Role)
		}
		if strings.TrimSpace(session.ChainOperatorID) != "" {
			t.Fatalf("session chain_operator_id=%q want empty", session.ChainOperatorID)
		}
	})

	t.Run("approval with empty chain operator id returns conflict", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "")
		putAdminSession(svc, "gpm-admin-decision-approve-empty-chain-id")
		body := `{"wallet_address":"cosmos1approvaldecision","approved":true,"session_token":"gpm-admin-decision-approve-empty-chain-id"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusConflict {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "chain_operator_id") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("approval with chain operator id returns approved status", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "operator-decision-4")
		putAdminSession(svc, "gpm-admin-decision-approve-chain-id")
		body := `{"wallet_address":"cosmos1approvaldecision","approved":true,"session_token":"gpm-admin-decision-approve-chain-id"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "approved" {
			t.Fatalf("decision=%q want=approved payload=%v", got, payload)
		}
		application, _ := payload["application"].(map[string]any)
		if got, _ := application["status"].(string); got != "approved" {
			t.Fatalf("application.status=%q want=approved payload=%v", got, payload)
		}
	})

	t.Run("response decision metadata for admin session auth", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "operator-decision-5")
		putAdminSession(svc, "gpm-admin-decision-metadata")
		body := `{"wallet_address":"cosmos1approvaldecision","approved":false,"reason":"policy mismatch","session_token":"gpm-admin-decision-metadata"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "rejected" {
			t.Fatalf("decision=%q want=rejected payload=%v", got, payload)
		}
		if got, _ := payload["decision_auth"].(string); got != "admin_session" {
			t.Fatalf("decision_auth=%q want=admin_session payload=%v", got, payload)
		}
	})

	t.Run("response decision metadata for legacy admin token auth", func(t *testing.T) {
		svc := newOperatorApproveDecisionService(t, "operator-decision-6")
		svc.gpmApprovalToken = "legacy-approval-token"
		body := `{"wallet_address":"cosmos1approvaldecision","approved":true,"admin_token":"legacy-approval-token"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "approved" {
			t.Fatalf("decision=%q want=approved payload=%v", got, payload)
		}
		if got, _ := payload["decision_auth"].(string); got != "legacy_admin_token" {
			t.Fatalf("decision_auth=%q want=legacy_admin_token payload=%v", got, payload)
		}
	})
}

func TestGPMOperatorApproveConcurrencyGuard(t *testing.T) {
	newOperatorApproveService := func(t *testing.T, updatedAt time.Time, chainOperatorID string) *Service {
		t.Helper()
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1approvalconcurrency",
			ChainOperatorID: chainOperatorID,
			Status:          "pending",
			UpdatedAt:       updatedAt,
		})
		return svc
	}
	putAdminSession := func(svc *Service, token string) {
		now := time.Now().UTC()
		svc.gpmState.putSession(gpmSession{
			Token:                  token,
			WalletAddress:          "cosmos1concurrencyadmin",
			WalletProvider:         "keplr",
			Role:                   "admin",
			WalletBindingVerified:  true,
			AuthVerificationSource: "command",
			CreatedAt:              now,
			ExpiresAt:              now.Add(time.Hour),
		})
		trustGPMAdminTestPolicy(svc, "cosmos1concurrencyadmin")
	}

	t.Run("invalid if_updated_at_utc returns bad request", func(t *testing.T) {
		updatedAt := time.Date(2026, time.January, 15, 4, 5, 6, 0, time.UTC)
		svc := newOperatorApproveService(t, updatedAt, "operator-concurrency-1")
		putAdminSession(svc, "gpm-admin-concurrency-invalid")

		body := `{"wallet_address":"cosmos1approvalconcurrency","approved":true,"if_updated_at_utc":"not-a-timestamp","session_token":"gpm-admin-concurrency-invalid"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "if_updated_at_utc") || !strings.Contains(errMsg, "RFC3339") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("stale if_updated_at_utc mismatch returns conflict", func(t *testing.T) {
		updatedAt := time.Date(2026, time.January, 15, 4, 5, 6, 0, time.UTC)
		svc := newOperatorApproveService(t, updatedAt, "operator-concurrency-2")
		putAdminSession(svc, "gpm-admin-concurrency-stale")
		stale := updatedAt.Add(-time.Minute).Format(time.RFC3339)

		body := `{"wallet_address":"cosmos1approvalconcurrency","approved":true,"if_updated_at_utc":"` + stale + `","session_token":"gpm-admin-concurrency-stale"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusConflict {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["ok"].(bool); got {
			t.Fatalf("ok=%v want=false payload=%v", got, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "stale") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
		if got, _ := payload["wallet_address"].(string); got != "cosmos1approvalconcurrency" {
			t.Fatalf("wallet_address=%q want=cosmos1approvalconcurrency payload=%v", got, payload)
		}
		if got, _ := payload["current_updated_at_utc"].(string); got != updatedAt.Format(time.RFC3339) {
			t.Fatalf("current_updated_at_utc=%q want=%q payload=%v", got, updatedAt.Format(time.RFC3339), payload)
		}
	})

	t.Run("matching if_updated_at_utc accepts stored nanosecond precision", func(t *testing.T) {
		updatedAt := time.Date(2026, time.January, 15, 4, 5, 6, 789_000_000, time.UTC)
		svc := newOperatorApproveService(t, updatedAt, "operator-concurrency-nanos")
		token := "gpm-admin-concurrency-nanos"
		putAdminSession(svc, token)

		body := `{"wallet_address":"cosmos1approvalconcurrency","approved":true,"if_updated_at_utc":"` + updatedAt.Format(time.RFC3339) + `","session_token":"` + token + `"}`
		code, payload := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		if got, _ := payload["decision"].(string); got != "approved" {
			t.Fatalf("decision=%q want=approved payload=%v", got, payload)
		}
	})

	t.Run("matching if_updated_at_utc allows approval and rejection", func(t *testing.T) {
		cases := []struct {
			name         string
			approved     bool
			reason       string
			wantDecision string
		}{
			{
				name:         "approval",
				approved:     true,
				wantDecision: "approved",
			},
			{
				name:         "rejection",
				approved:     false,
				reason:       "policy mismatch",
				wantDecision: "rejected",
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				updatedAt := time.Date(2026, time.January, 15, 4, 5, 6, 0, time.UTC)
				svc := newOperatorApproveService(t, updatedAt, "operator-concurrency-3")
				token := "gpm-admin-concurrency-match-" + tc.name
				putAdminSession(svc, token)

				payload := map[string]any{
					"wallet_address":    "cosmos1approvalconcurrency",
					"approved":          tc.approved,
					"if_updated_at_utc": updatedAt.Format(time.RFC3339),
					"session_token":     token,
				}
				if tc.reason != "" {
					payload["reason"] = tc.reason
				}
				bodyBytes, err := json.Marshal(payload)
				if err != nil {
					t.Fatalf("marshal body: %v", err)
				}

				code, out := callJSONHandler(t, svc.handleGPMOperatorApprove, http.MethodPost, "/v1/gpm/onboarding/operator/approve", string(bodyBytes))
				if code != http.StatusOK {
					t.Fatalf("status=%d payload=%v", code, out)
				}
				if got, _ := out["decision"].(string); got != tc.wantDecision {
					t.Fatalf("decision=%q want=%q payload=%v", got, tc.wantDecision, out)
				}
				application, _ := out["application"].(map[string]any)
				if got, _ := application["status"].(string); got != tc.wantDecision {
					t.Fatalf("application.status=%q want=%q payload=%v", got, tc.wantDecision, out)
				}
			})
		}
	})
}

func TestGPMClientRegisterRejectsPinnedMainDomainHostMismatch(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	var manifestHits int
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{"https://directory.globalprivatemesh.example:8081"},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = "https://pinned.globalprivatemesh.example:8443"
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token-mismatch"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1registeredclientmismatch",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "host mismatch") || !strings.Contains(errMsg, "pinned gpm main domain") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if manifestHits != 0 {
		t.Fatalf("expected manifest fetch to be blocked before contact, got %d hits", manifestHits)
	}
}

func TestGPMClientRegisterRejectsPinnedManifestHTTPURLWhenHTTPSRequired(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestTrustPolicyMode = "production"
	svc.gpmManifestRequireHTTPS = true
	svc.gpmMainDomain = "https://pinned.globalprivatemesh.example:8443"
	svc.gpmManifestURL = "http://pinned.globalprivatemesh.example:8443/v1/bootstrap/manifest"

	now := time.Now().UTC()
	const token = "gpm-session-token-http-manifest-blocked"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1httppinnedmanifest",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "must use https when pinned gpm main domain is configured") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestValidateManifestSourceURLPolicyRejectsUserinfoQueryAndFragment(t *testing.T) {
	svc := &Service{}
	tests := []struct {
		name          string
		sourceURL     string
		wantErrSubstr string
	}{
		{
			name:          "userinfo is rejected",
			sourceURL:     "https://operator:secret@bootstrap.globalprivatemesh.example/v1/bootstrap/manifest",
			wantErrSubstr: "userinfo",
		},
		{
			name:          "query is rejected",
			sourceURL:     "https://bootstrap.globalprivatemesh.example/v1/bootstrap/manifest?trace=1",
			wantErrSubstr: "query is not allowed",
		},
		{
			name:          "fragment is rejected",
			sourceURL:     "https://bootstrap.globalprivatemesh.example/v1/bootstrap/manifest#v2",
			wantErrSubstr: "fragment is not allowed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validateManifestSourceURLPolicy(tc.sourceURL, "", "cached manifest source url")
			if err == nil {
				t.Fatalf("expected source url %q to be rejected", tc.sourceURL)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("error=%q want contains %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

func TestValidateBootstrapManifestRejectsFutureGeneratedAtBeyondSkew(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(gpmManifestCacheFutureSkew + time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(gpmManifestCacheFutureSkew + time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.future-generated.globalprivatemesh.example:8081"},
	}

	err := validateBootstrapManifest(manifest)
	if err == nil {
		t.Fatal("expected future generated_at_utc to fail closed")
	}
	if !strings.Contains(err.Error(), "generated_at_utc is in the future") {
		t.Fatalf("error=%q want future generated_at_utc rejection", err.Error())
	}
}

func TestValidateBootstrapManifestRejectsTooManyBootstrapDirectories(t *testing.T) {
	now := time.Now().UTC()
	directories := make([]string, 0, gpmManifestBootstrapDirectoryMax+1)
	for i := 0; i < gpmManifestBootstrapDirectoryMax+1; i++ {
		directories = append(directories, fmt.Sprintf("https://directory-%02d.globalprivatemesh.example:8081", i))
	}
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: directories,
	}

	err := validateBootstrapManifest(manifest)
	if err == nil {
		t.Fatal("expected oversized bootstrap_directories to fail closed")
	}
	want := fmt.Sprintf("bootstrap_directories has %d items, max %d", gpmManifestBootstrapDirectoryMax+1, gpmManifestBootstrapDirectoryMax)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error=%q want contains %q", err.Error(), want)
	}
}

func TestValidateBootstrapManifestRejectsOverlongValidityWindow(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(gpmManifestMaxValidity + time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.overlong-validity.globalprivatemesh.example:8081"},
	}

	err := validateBootstrapManifest(manifest)
	if err == nil {
		t.Fatal("expected overlong manifest validity window to fail closed")
	}
	if !strings.Contains(err.Error(), "validity window exceeds maximum") {
		t.Fatalf("error=%q want validity window rejection", err.Error())
	}
}

func TestValidateBootstrapManifestEndpointHintsRequirePublicHTTPS(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	now := time.Now().UTC()
	newManifest := func() gpmBootstrapManifest {
		return gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.hints.globalprivatemesh.example:8081"},
			GatewayMirrors: []gpmBootstrapURLHint{{
				URL:  "https://mirror.hints.globalprivatemesh.example/v1/bootstrap/manifest",
				Kind: "mirror",
			}},
			BootstrapSources: []gpmBootstrapURLHint{{
				URL:  "https://source.hints.globalprivatemesh.example/v1/bootstrap/manifest",
				Kind: "primary",
			}},
			RelayHints: []gpmBootstrapRelayHint{{
				RelayID:    "relay-hints",
				OperatorID: "operator-hints",
				EntryURL:   "https://relay.hints.globalprivatemesh.example/entry",
				PublicHost: "relay.hints.globalprivatemesh.example",
				HintSource: "manifest",
			}},
			BridgeHints: []gpmBootstrapBridgeHint{{
				BridgeID:  "bridge-hints",
				Endpoint:  "https://bridge.hints.globalprivatemesh.example/bootstrap",
				Transport: "https",
			}},
		}
	}

	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch strings.TrimSpace(host) {
		case "private.hints.globalprivatemesh.example":
			return []net.IPAddr{{IP: net.ParseIP("10.12.0.8")}}, nil
		default:
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
	}

	if err := validateBootstrapManifest(newManifest()); err != nil {
		t.Fatalf("expected safe hint endpoints to validate: %v", err)
	}

	tests := []struct {
		name          string
		mutate        func(*gpmBootstrapManifest)
		wantErrSubstr string
	}{
		{
			name: "gateway mirror rejects javascript scheme",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.GatewayMirrors[0].URL = "javascript:alert(1)"
			},
			wantErrSubstr: "unsupported url scheme",
		},
		{
			name: "gateway mirror rejects remote http",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.GatewayMirrors[0].URL = "http://mirror.hints.globalprivatemesh.example/v1/bootstrap/manifest"
			},
			wantErrSubstr: "must use https",
		},
		{
			name: "bootstrap source rejects single label host",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.BootstrapSources[0].URL = "https://bootstrap/manifest"
			},
			wantErrSubstr: "single-label",
		},
		{
			name: "relay entry rejects private literal",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.RelayHints[0].EntryURL = "https://10.0.0.8/entry"
			},
			wantErrSubstr: "private, loopback, or link-local",
		},
		{
			name: "relay public host rejects scheme",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.RelayHints[0].PublicHost = "https://relay.hints.globalprivatemesh.example"
			},
			wantErrSubstr: "must not include scheme",
		},
		{
			name: "relay public host rejects private dns resolution",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.RelayHints[0].PublicHost = "private.hints.globalprivatemesh.example"
			},
			wantErrSubstr: "private, loopback, or link-local",
		},
		{
			name: "bridge endpoint rejects test net literal",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.BridgeHints[0].Endpoint = "https://203.0.113.10/bootstrap"
			},
			wantErrSubstr: "reserved or test-only",
		},
		{
			name: "bridge endpoint rejects http",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.BridgeHints[0].Endpoint = "http://bridge.hints.globalprivatemesh.example/bootstrap"
			},
			wantErrSubstr: "must use https",
		},
		{
			name: "bridge transport rejects arbitrary transport",
			mutate: func(manifest *gpmBootstrapManifest) {
				manifest.BridgeHints[0].Transport = "quic"
			},
			wantErrSubstr: "transport unsupported",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := newManifest()
			tc.mutate(&manifest)
			err := validateBootstrapManifest(manifest)
			if err == nil {
				t.Fatal("expected manifest endpoint hint to be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("error=%q want contains %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

func TestNormalizeBootstrapDirectoriesCanonicalizesURLs(t *testing.T) {
	got := normalizeBootstrapDirectories([]string{
		" HTTPS://Directory.GPM.Example:443/ ",
		"https://directory.gpm.example",
		"https://directory.gpm.example:8443/root/",
		"https://DIRECTORY.gpm.example:8443/root",
	})
	want := []string{
		"https://directory.gpm.example",
		"https://directory.gpm.example:8443/root",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("canonical bootstrap directories=%v want=%v", got, want)
	}
}

func TestFetchRemoteManifestWithPolicyProductionRejectsPrivateLoopbackAndLinkLocalTargets(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	tests := []struct {
		name        string
		manifestURL string
		lookupIPs   []net.IPAddr
	}{
		{
			name:        "literal loopback",
			manifestURL: "https://127.0.0.1:9443/v1/bootstrap/manifest",
		},
		{
			name:        "literal link local",
			manifestURL: "https://[fe80::1]/v1/bootstrap/manifest",
		},
		{
			name:        "dns private",
			manifestURL: "https://bootstrap.private.gpm.example/v1/bootstrap/manifest",
			lookupIPs:   []net.IPAddr{{IP: net.ParseIP("10.12.0.8")}},
		},
		{
			name:        "dns cgnat",
			manifestURL: "https://bootstrap.cgnat.gpm.example/v1/bootstrap/manifest",
			lookupIPs:   []net.IPAddr{{IP: net.ParseIP("100.64.12.8")}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
				return tc.lookupIPs, nil
			}
			svc := &Service{
				gpmManifestTrustPolicyMode: "production",
				gpmManifestRequireHTTPS:    true,
				gpmManifestURL:             tc.manifestURL,
			}
			_, _, _, _, err := svc.fetchRemoteManifestWithPolicy(context.Background(), tc.manifestURL)
			if err == nil {
				t.Fatalf("expected production manifest fetch target %q to fail closed", tc.manifestURL)
			}
			errMsg := err.Error()
			if !strings.Contains(errMsg, "production manifest outbound policy") {
				t.Fatalf("error=%q want production outbound policy rejection", errMsg)
			}
			if !strings.Contains(errMsg, "private, loopback, or link-local") && !strings.Contains(errMsg, "shared address space") {
				t.Fatalf("error=%q want private/loopback/link-local/shared-address rejection", errMsg)
			}
		})
	}
}

func TestReadBootstrapManifestCacheEnforcesSourceURLPolicyWithoutPinnedOrHTTPSRequirements(t *testing.T) {
	now := time.Now().UTC()
	cachePath := filepath.Join(t.TempDir(), "manifest_cache_source_policy.json")
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Format(time.RFC3339),
		SourceURL:         "ftp://bootstrap-cache.globalprivatemesh.example/v1/bootstrap/manifest",
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache-source-policy.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	svc := &Service{
		gpmMainDomain:           "",
		gpmManifestURL:          "https://bootstrap.globalprivatemesh.example/v1/bootstrap/manifest",
		gpmManifestCache:        cachePath,
		gpmManifestMaxAge:       24 * time.Hour,
		gpmManifestRequireHTTPS: false,
	}
	_, _, err = svc.readBootstrapManifestCache()
	if err == nil {
		t.Fatal("expected cached source_url policy enforcement without pinned host/https requirements")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "cached manifest source url") || !strings.Contains(errMsg, "unsupported url scheme") {
		t.Fatalf("error=%q want cached source url scheme validation failure", errMsg)
	}
}

func TestReadBootstrapManifestCacheProductionRejectsCachedSourceCGNATResolution(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("100.64.12.8")}}, nil
	}

	now := time.Now().UTC()
	cachePath := filepath.Join(t.TempDir(), "manifest_cache_source_cgnat.json")
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Format(time.RFC3339),
		SourceURL:         "https://bootstrap-cache-cgnat.globalprivatemesh.example/v1/bootstrap/manifest",
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache-cgnat.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	svc := &Service{
		gpmManifestURL:             "https://bootstrap-cache-cgnat.globalprivatemesh.example/v1/bootstrap/manifest",
		gpmManifestCache:           cachePath,
		gpmManifestMaxAge:          24 * time.Hour,
		gpmManifestRequireHTTPS:    true,
		gpmManifestTrustPolicyMode: "production",
	}
	_, _, err = svc.readBootstrapManifestCache()
	if err == nil {
		t.Fatal("expected production cached source URL outbound policy to fail closed")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "cached manifest source url") || !strings.Contains(errMsg, "shared address space") {
		t.Fatalf("error=%q want cached source production CGNAT rejection", errMsg)
	}
}

func TestReadBootstrapManifestCacheRejectsFutureFetchedAtBeyondSkew(t *testing.T) {
	now := time.Now().UTC()
	cachePath := filepath.Join(t.TempDir(), "manifest_cache_future_reject.json")
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(gpmManifestCacheFutureSkew + 3*time.Minute).Format(time.RFC3339),
		SourceURL:         "https://bootstrap-cache-future.globalprivatemesh.example/v1/bootstrap/manifest",
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache-future-reject.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	svc := &Service{
		gpmManifestCache:        cachePath,
		gpmManifestMaxAge:       24 * time.Hour,
		gpmManifestRequireHTTPS: false,
	}
	_, _, err = svc.readBootstrapManifestCache()
	if err == nil {
		t.Fatal("expected future fetched_at_utc to fail closed")
	}
	if !strings.Contains(err.Error(), "fetched_at_utc is in the future") {
		t.Fatalf("error=%q want future fetched_at_utc rejection", err.Error())
	}
}

func TestReadBootstrapManifestCacheAllowsSmallFutureFetchedAtWithinSkew(t *testing.T) {
	now := time.Now().UTC()
	cachePath := filepath.Join(t.TempDir(), "manifest_cache_future_within_skew.json")
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(gpmManifestCacheFutureSkew / 2).Format(time.RFC3339),
		SourceURL:         "https://bootstrap-cache-future.globalprivatemesh.example/v1/bootstrap/manifest",
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache-future-allow.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	svc := &Service{
		gpmManifestCache:        cachePath,
		gpmManifestMaxAge:       24 * time.Hour,
		gpmManifestRequireHTTPS: false,
	}
	manifest, signatureVerified, err := svc.readBootstrapManifestCache()
	if err != nil {
		t.Fatalf("readBootstrapManifestCache: %v", err)
	}
	if !signatureVerified {
		t.Fatalf("signatureVerified=%t want=true", signatureVerified)
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != "https://directory.cache-future-allow.globalprivatemesh.example:8081" {
		t.Fatalf("bootstrap_directories=%v want=[https://directory.cache-future-allow.globalprivatemesh.example:8081]", manifest.BootstrapDirectories)
	}
}

func TestFetchRemoteManifestSucceedsWithEd25519Signature(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.ed25519.globalprivatemesh.example:8081"},
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestBody))
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GPM-Signature-Ed25519", signature)
		_, _ = w.Write(manifestBody)
	}))
	t.Cleanup(manifestServer.Close)

	svc := &Service{
		gpmManifestEd25519PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}
	gotManifest, signatureVerified, _, _, err := svc.fetchRemoteManifest(context.Background(), manifestServer.URL)
	if err != nil {
		t.Fatalf("fetchRemoteManifest: %v", err)
	}
	if !signatureVerified {
		t.Fatalf("signatureVerified=%t want=true", signatureVerified)
	}
	if len(gotManifest.BootstrapDirectories) != 1 || gotManifest.BootstrapDirectories[0] != manifest.BootstrapDirectories[0] {
		t.Fatalf("bootstrap_directories=%v want=%v", gotManifest.BootstrapDirectories, manifest.BootstrapDirectories)
	}
}

func TestFetchRemoteManifestFailsClosedWithEd25519SignatureMissingOrInvalid(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.ed25519-fail.globalprivatemesh.example:8081"},
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	invalidSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(`{"tampered":true}`)))

	tests := []struct {
		name          string
		headerName    string
		headerValue   string
		wantErrSubstr string
	}{
		{
			name:          "missing signature header",
			wantErrSubstr: "manifest ed25519 signature header missing",
		},
		{
			name:          "invalid signature header",
			headerName:    "X-GPM-Signature-Ed25519",
			headerValue:   invalidSignature,
			wantErrSubstr: "manifest ed25519 signature verification failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.headerName != "" {
					w.Header().Set(tc.headerName, tc.headerValue)
				}
				_, _ = w.Write(manifestBody)
			}))
			t.Cleanup(manifestServer.Close)

			svc := &Service{
				gpmManifestEd25519PublicKey: base64.StdEncoding.EncodeToString(publicKey),
			}
			_, _, _, _, err := svc.fetchRemoteManifest(context.Background(), manifestServer.URL)
			if err == nil {
				t.Fatalf("expected ed25519 signature validation failure")
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("error=%q want contains %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

func TestReadBootstrapManifestCacheSucceedsWithEd25519SignedPayloadEvidence(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.cache-ed25519-ok.globalprivatemesh.example:8081"},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	manifestSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestPayload))

	cache := gpmBootstrapManifestCacheFile{
		Version:               1,
		FetchedAtUTC:          now.Format(time.RFC3339),
		SourceURL:             "https://bootstrap-cache-ed25519.globalprivatemesh.example/v1/bootstrap/manifest",
		SignatureVerified:     false,
		ManifestSignature:     manifestSignature,
		ManifestPayloadBase64: base64.StdEncoding.EncodeToString(manifestPayload),
		Manifest:              manifest,
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	cachePath := filepath.Join(t.TempDir(), "manifest_cache_ed25519_ok.json")
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	svc := &Service{
		gpmManifestCache:            cachePath,
		gpmManifestMaxAge:           24 * time.Hour,
		gpmManifestEd25519PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}
	gotManifest, signatureVerified, err := svc.readBootstrapManifestCache()
	if err != nil {
		t.Fatalf("readBootstrapManifestCache: %v", err)
	}
	if !signatureVerified {
		t.Fatalf("signatureVerified=%t want=true", signatureVerified)
	}
	if len(gotManifest.BootstrapDirectories) != 1 || gotManifest.BootstrapDirectories[0] != manifest.BootstrapDirectories[0] {
		t.Fatalf("bootstrap_directories=%v want=%v", gotManifest.BootstrapDirectories, manifest.BootstrapDirectories)
	}
}

func TestReadBootstrapManifestCacheFailsClosedWithEd25519MissingOrMismatchedSignedPayloadEvidence(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.cache-ed25519-fail.globalprivatemesh.example:8081"},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}

	newService := func(t *testing.T) *Service {
		t.Helper()
		return &Service{
			gpmManifestCache:            filepath.Join(t.TempDir(), "manifest_cache_ed25519_fail.json"),
			gpmManifestMaxAge:           24 * time.Hour,
			gpmManifestEd25519PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}
	}
	writeCache := func(t *testing.T, cachePath string, cache gpmBootstrapManifestCacheFile) {
		t.Helper()
		cacheBody, err := json.MarshalIndent(cache, "", "  ")
		if err != nil {
			t.Fatalf("marshal cache: %v", err)
		}
		if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
			t.Fatalf("write cache: %v", err)
		}
	}

	t.Run("missing signed payload evidence", func(t *testing.T) {
		svc := newService(t)
		cache := gpmBootstrapManifestCacheFile{
			Version:           1,
			FetchedAtUTC:      now.Format(time.RFC3339),
			SourceURL:         "https://bootstrap-cache-ed25519.globalprivatemesh.example/v1/bootstrap/manifest",
			SignatureVerified: true,
			Manifest:          manifest,
		}
		writeCache(t, svc.gpmManifestCache, cache)

		_, _, err := svc.readBootstrapManifestCache()
		if err == nil {
			t.Fatal("expected missing signed payload evidence error")
		}
		if !strings.Contains(err.Error(), "missing signed payload evidence") {
			t.Fatalf("error=%q want missing signed payload evidence", err.Error())
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		svc := newService(t)
		_, otherPrivateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("ed25519 keygen(other): %v", err)
		}
		cache := gpmBootstrapManifestCacheFile{
			Version:               1,
			FetchedAtUTC:          now.Format(time.RFC3339),
			SourceURL:             "https://bootstrap-cache-ed25519.globalprivatemesh.example/v1/bootstrap/manifest",
			SignatureVerified:     false,
			ManifestSignature:     base64.StdEncoding.EncodeToString(ed25519.Sign(otherPrivateKey, manifestPayload)),
			ManifestPayloadBase64: base64.StdEncoding.EncodeToString(manifestPayload),
			Manifest:              manifest,
		}
		writeCache(t, svc.gpmManifestCache, cache)

		_, _, err = svc.readBootstrapManifestCache()
		if err == nil {
			t.Fatal("expected signature mismatch error")
		}
		if !strings.Contains(err.Error(), "cached manifest signature verification failed") {
			t.Fatalf("error=%q want cached manifest signature verification failed", err.Error())
		}
	})

	t.Run("payload body mismatch", func(t *testing.T) {
		svc := newService(t)
		signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestPayload))
		cache := gpmBootstrapManifestCacheFile{
			Version:               1,
			FetchedAtUTC:          now.Format(time.RFC3339),
			SourceURL:             "https://bootstrap-cache-ed25519.globalprivatemesh.example/v1/bootstrap/manifest",
			SignatureVerified:     false,
			ManifestSignature:     signature,
			ManifestPayloadBase64: base64.StdEncoding.EncodeToString(manifestPayload),
			Manifest: gpmBootstrapManifest{
				Version:              1,
				GeneratedAtUTC:       manifest.GeneratedAtUTC,
				ExpiresAtUTC:         manifest.ExpiresAtUTC,
				BootstrapDirectories: []string{"https://directory.cache-ed25519-mismatch.globalprivatemesh.example:8081"},
			},
		}
		writeCache(t, svc.gpmManifestCache, cache)

		_, _, err := svc.readBootstrapManifestCache()
		if err == nil {
			t.Fatal("expected payload/body mismatch error")
		}
		if !strings.Contains(err.Error(), "cached manifest payload does not match cached manifest body") {
			t.Fatalf("error=%q want payload/body mismatch", err.Error())
		}
	})
}

func TestFetchRemoteManifestFailsClosedWhenSignatureRequiredWithoutVerifierKey(t *testing.T) {
	now := time.Now().UTC()
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{"https://directory.required-key.globalprivatemesh.example:8081"},
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(manifestBody)
	}))
	t.Cleanup(manifestServer.Close)

	svc := &Service{
		gpmManifestRequireSignature: true,
	}
	_, _, _, _, err = svc.fetchRemoteManifest(context.Background(), manifestServer.URL)
	if err == nil {
		t.Fatal("expected signature-required policy to fail closed without a verifier key")
	}
	if !strings.Contains(err.Error(), "verification key is required by policy") {
		t.Fatalf("error=%q want no verifier key guidance", err.Error())
	}
}

func TestReadBootstrapManifestCacheWithHMACKeyReverification(t *testing.T) {
	now := time.Now().UTC()

	newManifest := func(directory string) gpmBootstrapManifest {
		return gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{directory},
		}
	}

	newCacheService := func(t *testing.T, hmacKey string) *Service {
		t.Helper()
		manifestURL := "https://bootstrap-cache.globalprivatemesh.example/v1/bootstrap/manifest"
		return &Service{
			gpmMainDomain:      "https://bootstrap-cache.globalprivatemesh.example",
			gpmManifestURL:     manifestURL,
			gpmManifestCache:   filepath.Join(t.TempDir(), "manifest_cache.json"),
			gpmManifestMaxAge:  24 * time.Hour,
			gpmManifestHMACKey: hmacKey,
		}
	}

	t.Run("rejects tampered cached manifest when key is configured", func(t *testing.T) {
		svc := newCacheService(t, "manifest-cache-hmac-test-key")
		originalDirectory := "https://directory-trusted.globalprivatemesh.example:8081"
		tamperedDirectory := "https://directory-tampered.globalprivatemesh.example:8081"
		manifest := newManifest(originalDirectory)
		manifestBody, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		manifestSignature := computeManifestHMAC(manifestBody, svc.gpmManifestHMACKey)
		if err := svc.writeBootstrapManifestCache(manifest, true, manifestBody, manifestSignature); err != nil {
			t.Fatalf("write cache: %v", err)
		}
		cacheBody, err := os.ReadFile(svc.gpmManifestCache)
		if err != nil {
			t.Fatalf("read cache: %v", err)
		}
		tamperedBody := strings.Replace(string(cacheBody), originalDirectory, tamperedDirectory, 1)
		if tamperedBody == string(cacheBody) {
			t.Fatal("expected cache tamper replacement to modify payload")
		}
		if err := os.WriteFile(svc.gpmManifestCache, []byte(tamperedBody), 0o600); err != nil {
			t.Fatalf("write tampered cache: %v", err)
		}

		manifest, signatureVerified, err := svc.readBootstrapManifestCache()
		if err == nil {
			t.Fatalf("expected tampered cache to fail cryptographic re-verification, got manifest=%+v signature_verified=%t", manifest, signatureVerified)
		}
	})

	t.Run("accepts untampered cached manifest when key is configured", func(t *testing.T) {
		svc := newCacheService(t, "manifest-cache-hmac-test-key")
		directory := "https://directory-intact.globalprivatemesh.example:8081"
		manifest := newManifest(directory)
		manifestBody, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		manifestSignature := computeManifestHMAC(manifestBody, svc.gpmManifestHMACKey)
		if err := svc.writeBootstrapManifestCache(manifest, true, manifestBody, manifestSignature); err != nil {
			t.Fatalf("write cache: %v", err)
		}

		manifest, signatureVerified, err := svc.readBootstrapManifestCache()
		if err != nil {
			t.Fatalf("read cache: %v", err)
		}
		if !signatureVerified {
			t.Fatalf("signature_verified=%t want=true", signatureVerified)
		}
		if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != directory {
			t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{directory})
		}
	})

	t.Run("compatibility cache write does not force signature_verified true", func(t *testing.T) {
		svc := newCacheService(t, "")
		directory := "https://directory-compat-write.globalprivatemesh.example:8081"
		manifest := newManifest(directory)
		if err := svc.writeBootstrapManifestCache(manifest, false, nil, ""); err != nil {
			t.Fatalf("write cache: %v", err)
		}

		cacheBody, err := os.ReadFile(svc.gpmManifestCache)
		if err != nil {
			t.Fatalf("read cache: %v", err)
		}
		var cache gpmBootstrapManifestCacheFile
		if err := json.Unmarshal(cacheBody, &cache); err != nil {
			t.Fatalf("unmarshal cache: %v", err)
		}
		if cache.SignatureVerified {
			t.Fatalf("cache.signature_verified=%t want=false", cache.SignatureVerified)
		}

		gotManifest, signatureVerified, err := svc.readBootstrapManifestCache()
		if err != nil {
			t.Fatalf("read cache: %v", err)
		}
		if signatureVerified {
			t.Fatalf("signature_verified=%t want=false", signatureVerified)
		}
		if len(gotManifest.BootstrapDirectories) != 1 || gotManifest.BootstrapDirectories[0] != directory {
			t.Fatalf("bootstrap_directories=%v want=%v", gotManifest.BootstrapDirectories, []string{directory})
		}
	})

	t.Run("preserves legacy bool-only cache behavior when key is unset", func(t *testing.T) {
		svc := newCacheService(t, "")
		directory := "https://directory-legacy.globalprivatemesh.example:8081"
		cache := gpmBootstrapManifestCacheFile{
			Version:           1,
			FetchedAtUTC:      now.Format(time.RFC3339),
			SourceURL:         svc.gpmManifestURL,
			SignatureVerified: false,
			Manifest:          newManifest(directory),
		}
		cacheBody, err := json.MarshalIndent(cache, "", "  ")
		if err != nil {
			t.Fatalf("marshal legacy cache: %v", err)
		}
		if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
			t.Fatalf("write legacy cache: %v", err)
		}

		manifest, signatureVerified, err := svc.readBootstrapManifestCache()
		if err != nil {
			t.Fatalf("read legacy cache: %v", err)
		}
		if signatureVerified {
			t.Fatalf("signature_verified=%t want=false", signatureVerified)
		}
		if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != directory {
			t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{directory})
		}
	})
}

func TestGPMStateStoreLoadSkipsOversizedFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "gpm_state_oversized.json")
	oversized := strings.Repeat("A", gpmStateStoreLoadMaxBytes+1)
	if err := os.WriteFile(statePath, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write oversized state file: %v", err)
	}

	svc := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	svc.loadGPMStateBestEffort()

	sessions, _, _, _, _, _ := svc.gpmState.snapshotPersistent(time.Now().UTC())
	if len(sessions) != 0 {
		t.Fatalf("expected oversized state load to be skipped, sessions=%d", len(sessions))
	}
	if len(svc.gpmState.listOperators()) != 0 {
		t.Fatalf("expected oversized state load to be skipped, operators=%d", len(svc.gpmState.listOperators()))
	}
}

func TestReadBootstrapManifestCacheRejectsOversizedFile(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "manifest_cache_oversized.json")
	oversized := strings.Repeat("A", gpmManifestCacheBodyLimit+1)
	if err := os.WriteFile(cachePath, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write oversized cache file: %v", err)
	}

	svc := &Service{
		gpmManifestCache:  cachePath,
		gpmManifestMaxAge: 24 * time.Hour,
	}
	_, _, err := svc.readBootstrapManifestCache()
	if err == nil {
		t.Fatal("expected oversized cache file to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("error=%q want contains max size", err.Error())
	}
}

func TestGPMBootstrapManifestResponseIncludesTrustTelemetry(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}

	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 2 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 15 * time.Minute

	now := time.Now().UTC()
	manifestGeneratedAt := now.Add(-time.Minute).Format(time.RFC3339)
	manifestExpiresAt := now.Add(2 * time.Hour).Format(time.RFC3339)
	bootstrapDirectory := "https://directory.telemetry.globalprivatemesh.example:8081"
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      manifestGeneratedAt,
			"expires_at_utc":        manifestExpiresAt,
			"bootstrap_directories": []string{bootstrapDirectory},
			"gateway_mirrors": []map[string]any{
				{
					"url":  "https://mirror.telemetry.globalprivatemesh.example/v1/bootstrap/manifest",
					"kind": "mirror",
				},
			},
			"bridge_hints": []map[string]any{
				{
					"bridge_id":        "bridge-telemetry",
					"operator_id":      "op-bridge-telemetry",
					"endpoint":         "https://bridge.telemetry.globalprivatemesh.example/bootstrap",
					"transport":        "https",
					"ticket_required":  true,
					"rate_limit_class": "standard",
					"expires_at_utc":   manifestExpiresAt,
				},
			},
		})
	}))
	t.Cleanup(manifestServer.Close)

	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL
	expectedPinnedHost, err := normalizeHTTPHost(manifestServer.URL)
	if err != nil {
		t.Fatalf("normalize manifest server host: %v", err)
	}

	code, payload := callJSONHandler(t, svc.handleGPMBootstrapManifest, http.MethodGet, "/v1/gpm/bootstrap/manifest", "")
	if code != http.StatusOK {
		t.Fatalf("bootstrap manifest status=%d body=%v", code, payload)
	}

	if ok, _ := payload["ok"].(bool); !ok {
		t.Fatalf("ok=%v want=true payload=%v", payload["ok"], payload)
	}
	if got, _ := payload["source"].(string); got != "remote" {
		t.Fatalf("source=%q want=remote payload=%v", got, payload)
	}
	if signatureVerified, _ := payload["signature_verified"].(bool); signatureVerified {
		t.Fatalf("signature_verified=%v want=false payload=%v", signatureVerified, payload)
	}
	if got, _ := payload["trust_status"].(string); got != "trusted_remote_compat" {
		t.Fatalf("trust_status=%q want=trusted_remote_compat payload=%v", got, payload)
	}
	if got, _ := payload["manifest_expires_at_utc"].(string); got != manifestExpiresAt {
		t.Fatalf("manifest_expires_at_utc=%q want=%q payload=%v", got, manifestExpiresAt, payload)
	}
	if got, _ := payload["manifest_generated_at_utc"].(string); got != manifestGeneratedAt {
		t.Fatalf("manifest_generated_at_utc=%q want=%q payload=%v", got, manifestGeneratedAt, payload)
	}
	if got, _ := payload["manifest_source_url"].(string); got != manifestServer.URL {
		t.Fatalf("manifest_source_url=%q want=%q payload=%v", got, manifestServer.URL, payload)
	}
	if got, _ := payload["pinned_main_domain_host"].(string); got != expectedPinnedHost {
		t.Fatalf("pinned_main_domain_host=%q want=%q payload=%v", got, expectedPinnedHost, payload)
	}
	if got, _ := payload["signature_required_by_policy"].(bool); got {
		t.Fatalf("signature_required_by_policy=%v want=false payload=%v", got, payload)
	}
	if got, _ := payload["https_required_by_policy"].(bool); got {
		t.Fatalf("https_required_by_policy=%v want=false payload=%v", got, payload)
	}
	if got, _ := payload["cache_max_age_sec"].(float64); got != 7200 {
		t.Fatalf("cache_max_age_sec=%v want=7200 payload=%v", got, payload)
	}
	if got, _ := payload["remote_refresh_interval_sec"].(float64); got != 900 {
		t.Fatalf("remote_refresh_interval_sec=%v want=900 payload=%v", got, payload)
	}
	expiresInSec, _ := payload["manifest_expires_in_sec"].(float64)
	if expiresInSec <= 0 || expiresInSec > 7200 {
		t.Fatalf("manifest_expires_in_sec=%v want >0 and <=7200 payload=%v", expiresInSec, payload)
	}
	if _, hasWarning := payload["remote_refresh_warning"]; hasWarning {
		t.Fatalf("remote_refresh_warning should be absent for remote source payload=%v", payload)
	}
	manifestPayload, ok := payload["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("manifest type=%T want map payload=%v", payload["manifest"], payload)
	}
	if gotVersion, _ := manifestPayload["version"].(float64); gotVersion != 1 {
		t.Fatalf("manifest.version=%v want=1 manifest=%v", gotVersion, manifestPayload)
	}
	bridgeHints, ok := manifestPayload["bridge_hints"].([]any)
	if !ok || len(bridgeHints) != 1 {
		t.Fatalf("manifest.bridge_hints=%T/%v want one hint manifest=%v", manifestPayload["bridge_hints"], manifestPayload["bridge_hints"], manifestPayload)
	}
	bridgeHint, ok := bridgeHints[0].(map[string]any)
	if !ok {
		t.Fatalf("manifest.bridge_hints[0]=%T want map manifest=%v", bridgeHints[0], manifestPayload)
	}
	if got, _ := bridgeHint["bridge_id"].(string); got != "bridge-telemetry" {
		t.Fatalf("manifest.bridge_hints[0].bridge_id=%q want bridge-telemetry manifest=%v", got, manifestPayload)
	}
	gatewayMirrors, ok := manifestPayload["gateway_mirrors"].([]any)
	if !ok || len(gatewayMirrors) != 1 {
		t.Fatalf("manifest.gateway_mirrors=%T/%v want one mirror manifest=%v", manifestPayload["gateway_mirrors"], manifestPayload["gateway_mirrors"], manifestPayload)
	}
}

func TestGPMBootstrapManifestResponseIncludesRefreshWarningOnCacheFallback(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 30 * time.Second

	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-2 * time.Minute).Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache-warning.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	code, payload := callJSONHandler(t, svc.handleGPMBootstrapManifest, http.MethodGet, "/v1/gpm/bootstrap/manifest", "")
	if code != http.StatusOK {
		t.Fatalf("bootstrap manifest status=%d body=%v", code, payload)
	}

	if got, _ := payload["source"].(string); got != "cache" {
		t.Fatalf("source=%q want=cache payload=%v", got, payload)
	}
	if signatureVerified, _ := payload["signature_verified"].(bool); !signatureVerified {
		t.Fatalf("signature_verified=%v want=true payload=%v", signatureVerified, payload)
	}
	if got, _ := payload["trust_status"].(string); got != "trusted_cache" {
		t.Fatalf("trust_status=%q want=trusted_cache payload=%v", got, payload)
	}
	if got, _ := payload["manifest_source_url"].(string); got != manifestServer.URL {
		t.Fatalf("manifest_source_url=%q want=%q payload=%v", got, manifestServer.URL, payload)
	}
	warning, _ := payload["remote_refresh_warning"].(string)
	if !strings.Contains(warning, "periodic remote refresh failed") {
		t.Fatalf("remote_refresh_warning=%q want periodic refresh warning payload=%v", warning, payload)
	}
	if got, _ := payload["signature_required_by_policy"].(bool); got {
		t.Fatalf("signature_required_by_policy=%v want=false payload=%v", got, payload)
	}
}

func TestGPMClientRegisterUsesPinnedCacheFirstWhenCacheIsFresh(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	var manifestHits int
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const bootstrapDirectory = "https://directory.cache.globalprivatemesh.example:8081"
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{bootstrapDirectory},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	const token = "gpm-session-token-cache-fallback"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1cachefallback",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"2hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusOK {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	if manifestHits != 0 {
		t.Fatalf("expected cache-first registration to avoid remote refresh when cache is fresh, got %d hits", manifestHits)
	}

	source, _ := payload["source"].(string)
	if source != "cache" {
		t.Fatalf("source=%q want=cache payload=%v", source, payload)
	}
	signatureVerified, _ := payload["signature_verified"].(bool)
	if !signatureVerified {
		t.Fatalf("signature_verified=%v want=true payload=%v", signatureVerified, payload)
	}
	profile, _ := payload["profile"].(map[string]any)
	gotBootstrap, _ := profile["bootstrap_directory"].(string)
	if gotBootstrap != bootstrapDirectory {
		t.Fatalf("profile.bootstrap_directory=%q want=%q payload=%v", gotBootstrap, bootstrapDirectory, payload)
	}
}

func TestResolveBootstrapManifestRefreshesRemoteWhenCacheStillValidAndRefreshIntervalElapsed(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 30 * time.Second

	now := time.Now().UTC()
	remoteBootstrapDirectory := "https://directory.remote-refresh-interval.globalprivatemesh.example:8081"
	var manifestHits int
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{remoteBootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	validCache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-2 * time.Minute).Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.valid-cache.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(validCache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	manifest, source, _, err := svc.resolveBootstrapManifest(context.Background())
	if err != nil {
		t.Fatalf("resolve bootstrap manifest: %v", err)
	}
	if source != "remote" {
		t.Fatalf("source=%q want=remote", source)
	}
	if manifestHits == 0 {
		t.Fatal("expected valid cache with elapsed refresh interval to attempt bounded remote refresh")
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != remoteBootstrapDirectory {
		t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{remoteBootstrapDirectory})
	}
}

func TestResolveBootstrapManifestUsesConfiguredManifestURLWhenCachedSourceURLEmpty(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmMainDomain = ""
	svc.gpmManifestURL = "https://bootstrap-fallback.globalprivatemesh.example/v1/bootstrap/manifest"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache_empty_source_url.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 0

	now := time.Now().UTC()
	const cachedBootstrapDirectory = "https://directory.cache-empty-source-url.globalprivatemesh.example:8081"
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-15 * time.Second).Format(time.RFC3339),
		SourceURL:         "",
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{cachedBootstrapDirectory},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	manifest, source, signatureVerified, manifestSourceURL, remoteRefreshWarning, err := svc.resolveBootstrapManifestWithTelemetry(context.Background())
	if err != nil {
		t.Fatalf("resolve bootstrap manifest: %v", err)
	}
	if source != "cache" {
		t.Fatalf("source=%q want=cache", source)
	}
	if !signatureVerified {
		t.Fatalf("signatureVerified=%t want=true", signatureVerified)
	}
	if manifestSourceURL != svc.gpmManifestURL {
		t.Fatalf("manifestSourceURL=%q want=%q", manifestSourceURL, svc.gpmManifestURL)
	}
	if strings.TrimSpace(remoteRefreshWarning) != "" {
		t.Fatalf("remoteRefreshWarning=%q want empty", remoteRefreshWarning)
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != cachedBootstrapDirectory {
		t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{cachedBootstrapDirectory})
	}
}

func TestResolveBootstrapManifestFailsClosedWhenPeriodicRefreshFailsAndCacheAgeExceedsFallbackThreshold(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache_threshold_fail_closed.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 30 * time.Second
	svc.gpmManifestRefreshFailureMaxCacheAge = time.Minute

	now := time.Now().UTC()
	const cachedBootstrapDirectory = "https://directory.cache-threshold-fail-closed.globalprivatemesh.example:8081"
	var manifestHits int
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-2 * time.Minute).Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{cachedBootstrapDirectory},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	_, _, _, err = svc.resolveBootstrapManifest(context.Background())
	if err == nil {
		t.Fatal("expected periodic refresh failure with cache older than fallback threshold to fail closed")
	}
	if manifestHits == 0 {
		t.Fatal("expected periodic refresh to attempt remote call before fail-closed decision")
	}
}

func TestResolveBootstrapManifestFallsBackToTrustedCacheWhenPeriodicRefreshFailsWithinFallbackThreshold(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache_threshold_fallback.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 30 * time.Second
	svc.gpmManifestRefreshFailureMaxCacheAge = 2 * time.Minute

	now := time.Now().UTC()
	const cachedBootstrapDirectory = "https://directory.cache-threshold-fallback.globalprivatemesh.example:8081"
	var manifestHits int
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-90 * time.Second).Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{cachedBootstrapDirectory},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	manifest, source, signatureVerified, err := svc.resolveBootstrapManifest(context.Background())
	if err != nil {
		t.Fatalf("resolve bootstrap manifest: %v", err)
	}
	if source != "cache" {
		t.Fatalf("source=%q want=cache", source)
	}
	if !signatureVerified {
		t.Fatalf("signatureVerified=%t want=true", signatureVerified)
	}
	if manifestHits == 0 {
		t.Fatal("expected periodic refresh to attempt remote call before cache fallback")
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != cachedBootstrapDirectory {
		t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{cachedBootstrapDirectory})
	}
}

func TestResolveBootstrapManifestFallsBackToTrustedCacheWhenPeriodicRefreshFails(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestRemoteRefreshIntvl = 30 * time.Second

	now := time.Now().UTC()
	cachedBootstrapDirectory := "https://directory.cache-refresh-fallback.globalprivatemesh.example:8081"
	var manifestHits int
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	validCache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-2 * time.Minute).Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{cachedBootstrapDirectory},
		},
	}
	cacheBody, err := json.MarshalIndent(validCache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	manifest, source, signatureVerified, err := svc.resolveBootstrapManifest(context.Background())
	if err != nil {
		t.Fatalf("resolve bootstrap manifest: %v", err)
	}
	if source != "cache" {
		t.Fatalf("source=%q want=cache", source)
	}
	if !signatureVerified {
		t.Fatalf("signatureVerified=%t want=true", signatureVerified)
	}
	if manifestHits == 0 {
		t.Fatal("expected periodic refresh to attempt remote call before falling back to cache")
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != cachedBootstrapDirectory {
		t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{cachedBootstrapDirectory})
	}
}

func TestResolveBootstrapManifestRefreshesRemoteWhenCacheStale(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 30 * time.Second

	now := time.Now().UTC()
	remoteBootstrapDirectory := "https://directory.remote-refresh.globalprivatemesh.example:8081"
	var manifestHits int
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{remoteBootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	staleCache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Add(-2 * time.Minute).Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.stale-cache.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(staleCache, "", "  ")
	if err != nil {
		t.Fatalf("marshal stale cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write stale cache: %v", err)
	}

	manifest, source, _, err := svc.resolveBootstrapManifest(context.Background())
	if err != nil {
		t.Fatalf("resolve bootstrap manifest: %v", err)
	}
	if source != "remote" {
		t.Fatalf("source=%q want=remote", source)
	}
	if manifestHits == 0 {
		t.Fatal("expected stale cache to trigger a bounded remote manifest refresh")
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != remoteBootstrapDirectory {
		t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{remoteBootstrapDirectory})
	}

	cachedManifest, _, err := svc.readBootstrapManifestCache()
	if err != nil {
		t.Fatalf("read refreshed cache: %v", err)
	}
	if len(cachedManifest.BootstrapDirectories) != 1 || cachedManifest.BootstrapDirectories[0] != remoteBootstrapDirectory {
		t.Fatalf("refreshed cache bootstrap_directories=%v want=%v", cachedManifest.BootstrapDirectories, []string{remoteBootstrapDirectory})
	}
}

func TestResolveBootstrapManifestRefreshesRemoteWhenCacheMissing(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache_missing.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	now := time.Now().UTC()
	remoteBootstrapDirectory := "https://directory.remote-missing-cache.globalprivatemesh.example:8081"
	var manifestHits int
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{remoteBootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	manifest, source, _, err := svc.resolveBootstrapManifest(context.Background())
	if err != nil {
		t.Fatalf("resolve bootstrap manifest: %v", err)
	}
	if source != "remote" {
		t.Fatalf("source=%q want=remote", source)
	}
	if manifestHits == 0 {
		t.Fatal("expected missing cache to trigger a bounded remote manifest refresh")
	}
	if len(manifest.BootstrapDirectories) != 1 || manifest.BootstrapDirectories[0] != remoteBootstrapDirectory {
		t.Fatalf("bootstrap_directories=%v want=%v", manifest.BootstrapDirectories, []string{remoteBootstrapDirectory})
	}
}

func TestGPMClientRegisterRejectsPinnedCacheFallbackWithoutSignedPayloadEvidenceWhenHMACRequired(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestHMACKey = "test-manifest-hmac-key"

	var manifestHits int
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Format(time.RFC3339),
		SourceURL:         manifestServer.URL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	const token = "gpm-session-token-cache-hmac-missing-evidence"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1cachehmacevidence",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"2hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	if manifestHits == 0 {
		t.Fatal("expected remote manifest refresh attempt when cache is invalid")
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "manifest cache read failed") || !strings.Contains(errMsg, "missing signed payload evidence") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMClientRegisterRejectsCacheFallbackWhenSignatureRequiredButVerifierKeyMissing(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestRequireSignature = true
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmMainDomain = "https://127.0.0.1:1"
	svc.gpmManifestURL = "https://127.0.0.1:1/v1/bootstrap/manifest"

	now := time.Now().UTC()
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      now.Format(time.RFC3339),
		SourceURL:         svc.gpmManifestURL,
		SignatureVerified: true,
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.cache.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	const token = "gpm-session-token-cache-missing-key"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1cachemissingkey",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"2hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "manifest cache read failed") || !strings.Contains(errMsg, "verification key is required by policy") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMClientRegisterUsesPinnedCacheFirstWithSignedPayloadEvidenceWhenHMACRequired(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour
	svc.gpmManifestHMACKey = "test-manifest-hmac-key"

	var manifestHits int
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const bootstrapDirectory = "https://directory.cache.globalprivatemesh.example:8081"
	manifest := gpmBootstrapManifest{
		Version:              1,
		GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
		BootstrapDirectories: []string{bootstrapDirectory},
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest payload: %v", err)
	}
	manifestSignature := computeManifestHMAC(manifestPayload, svc.gpmManifestHMACKey)
	cache := gpmBootstrapManifestCacheFile{
		Version:               1,
		FetchedAtUTC:          now.Format(time.RFC3339),
		SourceURL:             manifestServer.URL,
		SignatureVerified:     false,
		ManifestSignature:     manifestSignature,
		ManifestPayloadBase64: base64.StdEncoding.EncodeToString(manifestPayload),
		Manifest:              manifest,
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(svc.gpmManifestCache, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	const token = "gpm-session-token-cache-hmac-verified"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1cachehmacverified",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"2hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusOK {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	if manifestHits != 0 {
		t.Fatalf("expected cache-first registration to avoid remote refresh when cache is fresh, got %d hits", manifestHits)
	}

	source, _ := payload["source"].(string)
	if source != "cache" {
		t.Fatalf("source=%q want=cache payload=%v", source, payload)
	}
	signatureVerified, _ := payload["signature_verified"].(bool)
	if !signatureVerified {
		t.Fatalf("signature_verified=%v want=true payload=%v", signatureVerified, payload)
	}
	profile, _ := payload["profile"].(map[string]any)
	gotBootstrap, _ := profile["bootstrap_directory"].(string)
	if gotBootstrap != bootstrapDirectory {
		t.Fatalf("profile.bootstrap_directory=%q want=%q payload=%v", gotBootstrap, bootstrapDirectory, payload)
	}
}

func TestGPMClientRegisterRejectsPinnedCacheFallbackSourceHostMismatch(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	cachePath := svc.gpmManifestCache
	cache := gpmBootstrapManifestCacheFile{
		Version:      1,
		FetchedAtUTC: now.Format(time.RFC3339),
		SourceURL:    "https://cache-source.globalprivatemesh.example:8443/v1/bootstrap/manifest",
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	const token = "gpm-session-token-cache-mismatch"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1cachemismatch",
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "manifest cache read failed") || !strings.Contains(errMsg, "cached manifest source host mismatch") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if !strings.Contains(errMsg, "pinned gpm main domain") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMStateStorePersistAndLoadRoundTrip(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	now := time.Now().UTC()
	expiresAt := now.Add(2 * time.Hour)

	svc := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	svc.gpmState.putSession(gpmSession{
		Token:              "persist-token",
		WalletAddress:      "cosmos1persist",
		WalletProvider:     "keplr",
		Role:               "operator",
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
		BootstrapDirectory: "https://directory.gpm.example:8081",
		BootstrapDirectories: []string{
			"https://directory.gpm.example:8081",
			"https://directory-backup.gpm.example:8081",
		},
		InviteKey:       "wallet:cosmos1persist",
		ChainOperatorID: "operator-persist-1",
	})
	svc.gpmState.upsertOperator(gpmOperatorApplication{
		WalletAddress:   "cosmos1persist",
		ChainOperatorID: "operator-persist-1",
		ServerLabel:     "persist-node",
		Status:          "approved",
		UpdatedAt:       now,
	})
	svc.persistGPMStateBestEffort("test_roundtrip")

	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state store: %v", err)
	}
	if strings.Contains(string(body), "persist-token") || strings.Contains(string(body), "wallet:cosmos1persist") {
		t.Fatalf("state store persisted bearer session material: %s", string(body))
	}
	var persisted gpmStateStoreFile
	if err := json.Unmarshal(body, &persisted); err != nil {
		t.Fatalf("decode state store: %v", err)
	}
	if len(persisted.Sessions) != 0 {
		t.Fatalf("persisted sessions=%d want 0; session tokens must not be written to disk", len(persisted.Sessions))
	}

	loaded := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	loaded.loadGPMStateBestEffort()

	if _, ok := loaded.gpmState.getSession("persist-token", now); ok {
		t.Fatal("session tokens must not survive state-store reload; user should re-authenticate after daemon restart")
	}

	operator, ok := loaded.gpmState.getOperator("cosmos1persist")
	if !ok {
		t.Fatal("expected persisted operator application to be loaded")
	}
	if operator.Status != "approved" {
		t.Fatalf("loaded operator status=%q want=approved", operator.Status)
	}
}

func TestGPMStateStoreProductionLoadSanitizesPersistedTrust(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	now := time.Now().UTC()
	store := gpmStateStoreFile{
		Version:        1,
		GeneratedAtUTC: now.Format(time.RFC3339),
		Sessions: []gpmSession{{
			Token:                     "persisted-prod-operator",
			WalletAddress:             "cosmos1persistedprod",
			WalletProvider:            "keplr",
			Role:                      "operator",
			WalletBindingVerified:     true,
			EntitlementEvidenceSource: "chain",
			ClientTier:                3,
			StakeSatisfied:            true,
			PrepaidBalanceSatisfied:   true,
			ChainOperatorID:           "operator-persisted-prod",
			CreatedAt:                 now,
			ExpiresAt:                 now.Add(time.Hour),
		}},
		Operators: []gpmOperatorApplication{{
			WalletAddress:          "cosmos1persistedprod",
			ChainOperatorID:        "operator-persisted-prod",
			Status:                 "approved",
			ApprovalEvidenceSource: "chain-governance",
			UpdatedAt:              now,
		}},
		Contributions: []gpmContributionState{{
			WalletAddress:           "cosmos1persistedprod",
			Enabled:                 true,
			Role:                    "micro-relay",
			RequestedRole:           "micro-relay",
			ClientTier:              3,
			StakeSatisfied:          true,
			PrepaidBalanceSatisfied: true,
			ExplicitOptIn:           true,
			PendingRewardUnits:      25,
			UpdatedAt:               now,
		}},
	}
	body, err := json.Marshal(store)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, body, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	loaded := &Service{
		gpmConnectPolicyMode: "production",
		gpmStateStorePath:    statePath,
		gpmState:             newGPMRuntimeState(),
	}
	loaded.loadGPMStateBestEffort()

	if _, ok := loaded.gpmState.getSession("persisted-prod-operator", now); ok {
		t.Fatal("legacy persisted session tokens must be stripped on load")
	}
	operator, ok := loaded.gpmState.getOperator("cosmos1persistedprod")
	if !ok {
		t.Fatal("expected persisted operator")
	}
	if operator.ApprovalEvidenceSource != "" {
		t.Fatalf("operator approval evidence source=%q want empty", operator.ApprovalEvidenceSource)
	}
	contribution, ok := loaded.gpmState.getContribution("cosmos1persistedprod")
	if !ok {
		t.Fatal("expected persisted contribution")
	}
	if contribution.Enabled {
		t.Fatalf("contribution enabled=%v want false", contribution.Enabled)
	}
	if contribution.PendingRewardUnits != 0 {
		t.Fatalf("pending reward units=%v want 0", contribution.PendingRewardUnits)
	}
	if !strings.Contains(contribution.LockReason, "fresh trusted chain") {
		t.Fatalf("lock reason=%q want fresh trusted chain guidance", contribution.LockReason)
	}
}

func TestGPMAuditAppendWritesJSONLine(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		gpmAuditLogPath: auditPath,
	}

	svc.appendGPMAudit("auth_verified", map[string]any{
		"wallet_address": "cosmos1audit",
		"role":           "client",
	})

	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit lines=%d want=1 body=%q", len(lines), string(body))
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if record["event"] != "auth_verified" {
		t.Fatalf("event=%v want=auth_verified", record["event"])
	}
	fields, _ := record["fields"].(map[string]any)
	if fields["wallet_address"] != "cosmos1audit" {
		t.Fatalf("wallet_address=%v want=cosmos1audit", fields["wallet_address"])
	}
}

func TestGPMAuditRecentHandlerDefaultBehavior(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("event_one", map[string]any{"idx": 1})
	svc.appendGPMAudit("event_two", map[string]any{"idx": 2})

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}

	count, _ := payload["count"].(float64)
	if int(count) != 2 {
		t.Fatalf("count=%v want=2 payload=%v", count, payload)
	}
	total, _ := payload["total"].(float64)
	if int(total) != 2 {
		t.Fatalf("total=%v want=2 payload=%v", total, payload)
	}
	limit, _ := payload["limit"].(float64)
	if int(limit) != 25 {
		t.Fatalf("limit=%v want=25 payload=%v", limit, payload)
	}
	offset, _ := payload["offset"].(float64)
	if int(offset) != 0 {
		t.Fatalf("offset=%v want=0 payload=%v", offset, payload)
	}
	nextOffset, _ := payload["next_offset"].(float64)
	if int(nextOffset) != 2 {
		t.Fatalf("next_offset=%v want=2 payload=%v", nextOffset, payload)
	}
	hasMore, _ := payload["has_more"].(bool)
	if hasMore {
		t.Fatalf("has_more=%v want=false payload=%v", hasMore, payload)
	}
	filters, _ := payload["filters"].(map[string]any)
	if got, _ := filters["event"].(string); got != "" {
		t.Fatalf("filters.event=%q want empty payload=%v", got, payload)
	}
	if got, _ := filters["wallet_address"].(string); got != "" {
		t.Fatalf("filters.wallet_address=%q want empty payload=%v", got, payload)
	}
	if got, _ := filters["order"].(string); got != "desc" {
		t.Fatalf("filters.order=%q want=desc payload=%v", got, payload)
	}
	if surface, _ := payload["admin_api_surface"].(string); surface != "gpm_admin_console" {
		t.Fatalf("admin_api_surface=%q want=gpm_admin_console payload=%v", surface, payload)
	}
	if publicControls, _ := payload["public_app_admin_controls"].(bool); publicControls {
		t.Fatalf("public_app_admin_controls=%v want=false payload=%v", publicControls, payload)
	}

	entries, _ := payload["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries len=%d want=2 payload=%v", len(entries), payload)
	}
	entry, _ := entries[0].(map[string]any)
	if event, _ := entry["event"].(string); event != "event_two" {
		t.Fatalf("event=%q want=event_two entry=%v", event, entry)
	}
	entry, _ = entries[1].(map[string]any)
	if event, _ := entry["event"].(string); event != "event_one" {
		t.Fatalf("event=%q want=event_one entry=%v", event, entry)
	}
}

func TestGPMAuditRecentHandlerRequiresAdminSession(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("event_one", map[string]any{"idx": 1})

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "")
	if code != http.StatusBadRequest {
		t.Fatalf("missing admin session status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "session_token is required") {
		t.Fatalf("missing admin error=%q payload=%v", errMsg, payload)
	}

	adminQueryToken := seedGPMAdminTestSession(t, svc, "gpm-audit-query-admin-token", "cosmos1auditqueryadmin")
	code, payload = callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?session_token="+adminQueryToken, "")
	if code != http.StatusBadRequest {
		t.Fatalf("query admin session status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "X-GPM-Session-Token") {
		t.Fatalf("query admin error=%q payload=%v", errMsg, payload)
	}

	code, payload = callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?session_token=leaked-token", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusBadRequest {
		t.Fatalf("query plus header admin session status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}

	clientToken := seedGPMTestSession(t, svc, "gpm-audit-client-token", "cosmos1auditclient", 2, true, true)
	code, payload = callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "", map[string]string{"X-GPM-Session-Token": clientToken})
	if code != http.StatusForbidden {
		t.Fatalf("non-admin audit status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "admin session role") {
		t.Fatalf("non-admin audit error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMAuditRecentHandlerLimitQueryBackwardCompatible(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("event_one", map[string]any{"idx": 1})
	svc.appendGPMAudit("event_two", map[string]any{"idx": 2})

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?limit=1", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	count, _ := payload["count"].(float64)
	if int(count) != 1 {
		t.Fatalf("count=%v want=1 payload=%v", count, payload)
	}
	total, _ := payload["total"].(float64)
	if int(total) != 2 {
		t.Fatalf("total=%v want=2 payload=%v", total, payload)
	}
	limit, _ := payload["limit"].(float64)
	if int(limit) != 1 {
		t.Fatalf("limit=%v want=1 payload=%v", limit, payload)
	}
	hasMore, _ := payload["has_more"].(bool)
	if !hasMore {
		t.Fatalf("has_more=%v want=true payload=%v", hasMore, payload)
	}
	nextOffset, _ := payload["next_offset"].(float64)
	if int(nextOffset) != 1 {
		t.Fatalf("next_offset=%v want=1 payload=%v", nextOffset, payload)
	}
	entries, _ := payload["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries len=%d want=1 payload=%v", len(entries), payload)
	}
	entry, _ := entries[0].(map[string]any)
	if event, _ := entry["event"].(string); event != "event_two" {
		t.Fatalf("event=%q want=event_two entry=%v", event, entry)
	}
}

func TestGPMAuditRecentHandlerEventFilter(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("auth_verified", map[string]any{"idx": 1})
	svc.appendGPMAudit("session_refreshed", map[string]any{"idx": 2})
	svc.appendGPMAudit("AUTH_VERIFIED", map[string]any{"idx": 3})

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?event=AuTh_VeRiFiEd", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	count, _ := payload["count"].(float64)
	if int(count) != 2 {
		t.Fatalf("count=%v want=2 payload=%v", count, payload)
	}
	total, _ := payload["total"].(float64)
	if int(total) != 2 {
		t.Fatalf("total=%v want=2 payload=%v", total, payload)
	}
	filters, _ := payload["filters"].(map[string]any)
	if got, _ := filters["event"].(string); got != "auth_verified" {
		t.Fatalf("filters.event=%q want=auth_verified payload=%v", got, payload)
	}
	entries, _ := payload["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries len=%d want=2 payload=%v", len(entries), payload)
	}
	first, _ := entries[0].(map[string]any)
	if event, _ := first["event"].(string); event != "AUTH_VERIFIED" {
		t.Fatalf("event[0]=%q want=AUTH_VERIFIED payload=%v", event, payload)
	}
	second, _ := entries[1].(map[string]any)
	if event, _ := second["event"].(string); event != "auth_verified" {
		t.Fatalf("event[1]=%q want=auth_verified payload=%v", event, payload)
	}
}

func TestGPMAuditRecentHandlerWalletFilter(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("auth_verified", map[string]any{"wallet_address": "Cosmos1WalletA"})
	svc.appendGPMAudit("session_refreshed", map[string]any{"wallet_address": "cosmos1walletb"})
	svc.appendGPMAudit("session_revoked", map[string]any{"role": "client"})

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?wallet_address=COSMOS1WALLETA", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	count, _ := payload["count"].(float64)
	if int(count) != 1 {
		t.Fatalf("count=%v want=1 payload=%v", count, payload)
	}
	total, _ := payload["total"].(float64)
	if int(total) != 1 {
		t.Fatalf("total=%v want=1 payload=%v", total, payload)
	}
	filters, _ := payload["filters"].(map[string]any)
	if got, _ := filters["wallet_address"].(string); got != "cosmos1walleta" {
		t.Fatalf("filters.wallet_address=%q want=cosmos1walleta payload=%v", got, payload)
	}
	entries, _ := payload["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries len=%d want=1 payload=%v", len(entries), payload)
	}
	entry, _ := entries[0].(map[string]any)
	if event, _ := entry["event"].(string); event != "auth_verified" {
		t.Fatalf("event=%q want=auth_verified entry=%v", event, entry)
	}
}

func TestGPMAuditRecentHandlerOffsetPagingMetadata(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("event_one", map[string]any{"idx": 1})
	svc.appendGPMAudit("event_two", map[string]any{"idx": 2})
	svc.appendGPMAudit("event_three", map[string]any{"idx": 3})
	svc.appendGPMAudit("event_four", map[string]any{"idx": 4})

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?limit=2&offset=1&order=desc", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	total, _ := payload["total"].(float64)
	if int(total) != 4 {
		t.Fatalf("total=%v want=4 payload=%v", total, payload)
	}
	count, _ := payload["count"].(float64)
	if int(count) != 2 {
		t.Fatalf("count=%v want=2 payload=%v", count, payload)
	}
	offset, _ := payload["offset"].(float64)
	if int(offset) != 1 {
		t.Fatalf("offset=%v want=1 payload=%v", offset, payload)
	}
	hasMore, _ := payload["has_more"].(bool)
	if !hasMore {
		t.Fatalf("has_more=%v want=true payload=%v", hasMore, payload)
	}
	nextOffset, _ := payload["next_offset"].(float64)
	if int(nextOffset) != 3 {
		t.Fatalf("next_offset=%v want=3 payload=%v", nextOffset, payload)
	}
	filters, _ := payload["filters"].(map[string]any)
	if got, _ := filters["order"].(string); got != "desc" {
		t.Fatalf("filters.order=%q want=desc payload=%v", got, payload)
	}
	entries, _ := payload["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries len=%d want=2 payload=%v", len(entries), payload)
	}
	first, _ := entries[0].(map[string]any)
	if event, _ := first["event"].(string); event != "event_three" {
		t.Fatalf("event[0]=%q want=event_three payload=%v", event, payload)
	}
	second, _ := entries[1].(map[string]any)
	if event, _ := second["event"].(string); event != "event_two" {
		t.Fatalf("event[1]=%q want=event_two payload=%v", event, payload)
	}
}

func TestGPMAuditRecentHandlerRejectsInvalidOrder(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?order=sideways", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "order must be one of") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMAuditRecentHandlerRejectsInvalidWalletFilter(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?wallet_address=bad!", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "wallet_address") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMAuditRecentHandlerRejectsOversizedAuditFile(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	oversized := strings.Repeat("A", gpmAuditReadMaxBytes+1)
	if err := os.WriteFile(auditPath, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write audit file: %v", err)
	}
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "", auditRecentAdminHeaders(t, svc))
	if code != http.StatusInternalServerError {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "maximum readable size") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMGapSummaryHandlerSuccess(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "gpm_gap_scan_summary.json")
	summaryBody, err := json.MarshalIndent(map[string]any{
		"version": 1,
		"schema": map[string]any{
			"id":    "gpm_gap_scan_summary",
			"major": 1,
			"minor": 0,
		},
		"generated_at_utc": time.Now().UTC().Format(time.RFC3339),
		"status":           "ok",
		"counts": map[string]any{
			"in_progress":  1,
			"missing_next": 2,
			"total":        3,
		},
		"items": []map[string]any{
			{
				"id":              "in_progress_01",
				"section":         "in_progress",
				"ordinal":         1,
				"text":            "Finish relay telemetry contract",
				"normalized_text": "finish relay telemetry contract",
			},
			{
				"id":              "missing_next_01",
				"section":         "missing_next",
				"ordinal":         1,
				"text":            "Wire strict relay trust binding",
				"normalized_text": "wire strict relay trust binding",
			},
			{
				"id":              "missing_next_02",
				"section":         "missing_next",
				"ordinal":         2,
				"text":            "Publish operator evidence pack",
				"normalized_text": "publish operator evidence pack",
			},
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal summary fixture: %v", err)
	}
	if err := os.WriteFile(summaryPath, summaryBody, 0o600); err != nil {
		t.Fatalf("write summary fixture: %v", err)
	}

	svc := &Service{
		addr:                  "127.0.0.1:8095",
		allowUnauthLoopback:   true,
		gpmGapScanSummaryPath: summaryPath,
		gpmState:              newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "", gpmAdminSessionHeaders(t, svc, "gpm-gaps-admin-token", "cosmos1gapsadmin"))
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if ok, _ := payload["ok"].(bool); !ok {
		t.Fatalf("ok=%v payload=%v", ok, payload)
	}
	if status, _ := payload["status"].(string); status != "ok" {
		t.Fatalf("status=%q want=ok payload=%v", status, payload)
	}
	if gotPath, _ := payload["artifact_path"].(string); gotPath != summaryPath {
		t.Fatalf("artifact_path=%q want=%q payload=%v", gotPath, summaryPath, payload)
	}

	counts, _ := payload["counts"].(map[string]any)
	if counts == nil {
		t.Fatalf("counts missing payload=%v", payload)
	}
	if got, _ := counts["in_progress"].(float64); int(got) != 1 {
		t.Fatalf("counts.in_progress=%v want=1 payload=%v", got, payload)
	}
	if got, _ := counts["missing_next"].(float64); int(got) != 2 {
		t.Fatalf("counts.missing_next=%v want=2 payload=%v", got, payload)
	}
	if got, _ := counts["total"].(float64); int(got) != 3 {
		t.Fatalf("counts.total=%v want=3 payload=%v", got, payload)
	}

	keyGaps, _ := payload["key_gaps"].([]any)
	if len(keyGaps) != 2 {
		t.Fatalf("key_gaps len=%d want=2 payload=%v", len(keyGaps), payload)
	}
	if got, _ := keyGaps[0].(string); got != "Wire strict relay trust binding" {
		t.Fatalf("key_gaps[0]=%q want=%q payload=%v", got, "Wire strict relay trust binding", payload)
	}
	nextActions, _ := payload["next_actions"].([]any)
	if len(nextActions) != 2 {
		t.Fatalf("next_actions len=%d want=2 payload=%v", len(nextActions), payload)
	}
	if got, _ := nextActions[1].(string); got != "Publish operator evidence pack" {
		t.Fatalf("next_actions[1]=%q want=%q payload=%v", got, "Publish operator evidence pack", payload)
	}
}

func TestGPMGapSummaryHandlerRequiresAdminSession(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "gpm_gap_scan_summary.json")
	body := []byte(`{"schema":{"id":"gpm_gap_scan_summary"},"status":"ok","generated_at_utc":"` + time.Now().UTC().Format(time.RFC3339) + `","counts":{"in_progress":0,"missing_next":0,"total":0},"items":[]}`)
	if err := os.WriteFile(summaryPath, body, 0o600); err != nil {
		t.Fatalf("write summary fixture: %v", err)
	}
	svc := &Service{
		addr:                  "127.0.0.1:8095",
		allowUnauthLoopback:   true,
		gpmGapScanSummaryPath: summaryPath,
		gpmState:              newGPMRuntimeState(),
	}

	code, payload := callJSONHandler(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "")
	if code != http.StatusBadRequest {
		t.Fatalf("missing admin session status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "session_token is required") {
		t.Fatalf("missing admin error=%q payload=%v", errMsg, payload)
	}

	queryToken := seedGPMAdminTestSession(t, svc, "gpm-gaps-query-admin-token", "cosmos1gapsqueryadmin")
	code, payload = callJSONHandler(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary?session_token="+queryToken, "")
	if code != http.StatusBadRequest {
		t.Fatalf("query admin session status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "X-GPM-Session-Token") {
		t.Fatalf("query admin error=%q payload=%v", errMsg, payload)
	}

	code, payload = callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary?session_token=leaked-token", "", gpmAdminSessionHeaders(t, svc, "gpm-gaps-query-plus-header-admin-token", "cosmos1gapsqueryheaderadmin"))
	if code != http.StatusBadRequest {
		t.Fatalf("query plus header admin session status=%d want=%d payload=%v", code, http.StatusBadRequest, payload)
	}

	clientToken := seedGPMTestSession(t, svc, "gpm-gaps-client-token", "cosmos1gapsclient", 2, true, true)
	code, payload = callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "", map[string]string{"X-GPM-Session-Token": clientToken})
	if code != http.StatusForbidden {
		t.Fatalf("client session status=%d want=%d payload=%v", code, http.StatusForbidden, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(errMsg, "admin session role") {
		t.Fatalf("client session error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMGapSummaryHandlerMissingArtifactFailsClosed(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "missing_gpm_gap_scan_summary.json")
	svc := &Service{
		addr:                  "127.0.0.1:8095",
		allowUnauthLoopback:   true,
		gpmGapScanSummaryPath: summaryPath,
		gpmState:              newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "", gpmAdminSessionHeaders(t, svc, "gpm-gaps-missing-admin-token", "cosmos1gapsmissingadmin"))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if status, _ := payload["status"].(string); status != "artifact_missing" {
		t.Fatalf("status=%q want=artifact_missing payload=%v", status, payload)
	}
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("ok=%v want=false payload=%v", ok, payload)
	}
}

func TestGPMGapSummaryHandlerMalformedArtifactFailsClosed(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "malformed_gpm_gap_scan_summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{"schema":{"id":"gpm_gap_scan_summary"},"status":"ok","counts":{"in_progress":1}}`), 0o600); err != nil {
		t.Fatalf("write malformed summary fixture: %v", err)
	}
	svc := &Service{
		addr:                  "127.0.0.1:8095",
		allowUnauthLoopback:   true,
		gpmGapScanSummaryPath: summaryPath,
		gpmState:              newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "", gpmAdminSessionHeaders(t, svc, "gpm-gaps-malformed-admin-token", "cosmos1gapsmalformedadmin"))
	if code != http.StatusInternalServerError {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if status, _ := payload["status"].(string); status != "artifact_malformed" {
		t.Fatalf("status=%q want=artifact_malformed payload=%v", status, payload)
	}
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("ok=%v want=false payload=%v", ok, payload)
	}
}

func TestGPMGapSummaryHandlerStaleArtifactFailsClosed(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "stale_gpm_gap_scan_summary.json")
	staleGeneratedAt := time.Now().UTC().Add(-(gpmGapSummaryMaxAge + time.Hour)).Format(time.RFC3339)
	body := []byte(`{"schema":{"id":"gpm_gap_scan_summary"},"status":"ok","generated_at_utc":"` + staleGeneratedAt + `","counts":{"in_progress":0,"missing_next":0,"total":0},"items":[]}`)
	if err := os.WriteFile(summaryPath, body, 0o600); err != nil {
		t.Fatalf("write stale summary fixture: %v", err)
	}
	svc := &Service{
		addr:                  "127.0.0.1:8095",
		allowUnauthLoopback:   true,
		gpmGapScanSummaryPath: summaryPath,
		gpmState:              newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "", gpmAdminSessionHeaders(t, svc, "gpm-gaps-stale-admin-token", "cosmos1gapsstaleadmin"))
	if code != http.StatusInternalServerError {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if status, _ := payload["status"].(string); status != "artifact_malformed" {
		t.Fatalf("status=%q want=artifact_malformed payload=%v", status, payload)
	}
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("ok=%v want=false payload=%v", ok, payload)
	}
	if errMsg, _ := payload["error"].(string); !strings.Contains(strings.ToLower(errMsg), "stale") {
		t.Fatalf("error=%q want stale marker payload=%v", errMsg, payload)
	}
}

func TestGPMGapSummaryHandlerMethodNotAllowed(t *testing.T) {
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmState:            newGPMRuntimeState(),
	}

	code, payload := callJSONHandler(t, svc.handleGPMGapSummary, http.MethodPost, "/v1/gpm/gaps/summary", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if got, _ := payload["error"].(string); got != "method not allowed" {
		t.Fatalf("error=%q want=method not allowed payload=%v", got, payload)
	}
}

func TestGPMGapSummaryHandlerOversizedArtifactFailsClosed(t *testing.T) {
	summaryPath := filepath.Join(t.TempDir(), "oversized_gpm_gap_scan_summary.json")
	body := []byte("{\"schema\":{\"id\":\"gpm_gap_scan_summary\"},\"status\":\"ok\",\"generated_at_utc\":\"" + time.Now().UTC().Format(time.RFC3339) + "\",\"counts\":{\"in_progress\":0,\"missing_next\":0,\"total\":0},\"items\":[]}")
	padding := strings.Repeat("x", gpmGapScanSummaryBodyLimit)
	if err := os.WriteFile(summaryPath, append(body, []byte(padding)...), 0o600); err != nil {
		t.Fatalf("write oversized summary fixture: %v", err)
	}

	svc := &Service{
		addr:                  "127.0.0.1:8095",
		allowUnauthLoopback:   true,
		gpmGapScanSummaryPath: summaryPath,
		gpmState:              newGPMRuntimeState(),
	}

	code, payload := callJSONHandlerWithHeaders(t, svc.handleGPMGapSummary, http.MethodGet, "/v1/gpm/gaps/summary", "", gpmAdminSessionHeaders(t, svc, "gpm-gaps-oversized-admin-token", "cosmos1gapsoversizedadmin"))
	if code != http.StatusInternalServerError {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	if status, _ := payload["status"].(string); status != "artifact_unreadable" {
		t.Fatalf("status=%q want=artifact_unreadable payload=%v", status, payload)
	}
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("ok=%v want=false payload=%v", ok, payload)
	}
}
