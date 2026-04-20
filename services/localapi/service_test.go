package localapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
)

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
    if [[ -n "${LOCALAPI_TEST_UP_FAIL_BOOTSTRAP:-}" && "$bootstrap_directory" == "${LOCALAPI_TEST_UP_FAIL_BOOTSTRAP}" ]]; then
      echo "connect failed"
      exit 43
    fi
    if [[ "${LOCALAPI_TEST_UP_FAIL:-0}" == "1" ]]; then
      echo "connect failed"
      exit 43
    fi
    echo "connect ok"
    ;;
  client-vpn-status)
    if [[ "${LOCALAPI_TEST_STATUS_FAIL:-0}" == "1" ]]; then
      echo "status failed"
      exit 44
    fi
    if [[ "${LOCALAPI_TEST_STATUS_RAW:-0}" == "1" ]]; then
      echo "status-raw"
    else
      echo '{"connected":true,"profile":"2hop"}'
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
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")

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
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
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
		if got := len(s.gpmLegacyEnvAliasesActive); got != 0 {
			t.Fatalf("gpmLegacyEnvAliasesActive len=%d want=0", got)
		}
		if got := len(s.gpmLegacyEnvAliasWarnings); got != 0 {
			t.Fatalf("gpmLegacyEnvAliasWarnings len=%d want=0", got)
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
	})

	t.Run("tdpn aliases enable new auth verify policies", func(t *testing.T) {
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "1")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "1")

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

		s := New()

		wantAliases := map[string]struct{}{
			"TDPN_MAIN_DOMAIN":                  {},
			"TDPN_PRODUCTION_MODE":              {},
			"TDPN_CONNECT_REQUIRE_SESSION":      {},
			"TDPN_AUTH_VERIFY_REQUIRE_METADATA": {},
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
		if got, want := len(s.gpmLegacyEnvAliasWarnings), 4; got != want {
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
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")

		s := New()
		if !s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=true", s.gpmConnectRequireSession)
		}
		if s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=false", s.gpmAllowLegacyConnectOverride)
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
	})

	t.Run("explicit connect and auth policy flags override production defaults", func(t *testing.T) {
		t.Setenv("GPM_PRODUCTION_MODE", "1")
		t.Setenv("GPM_CONNECT_REQUIRE_SESSION", "0")
		t.Setenv("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", "1")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "0")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", "")
		t.Setenv("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "")
		t.Setenv("TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", "0")
		t.Setenv("TDPN_CONNECT_REQUIRE_SESSION", "")
		t.Setenv("TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_COMMAND", "0")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_COMMAND", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_METADATA", "0")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_METADATA", "")
		t.Setenv("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "")
		t.Setenv("TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", "0")

		s := New()
		if s.gpmConnectRequireSession {
			t.Fatalf("gpmConnectRequireSession=%t want=false", s.gpmConnectRequireSession)
		}
		if !s.gpmAllowLegacyConnectOverride {
			t.Fatalf("gpmAllowLegacyConnectOverride=%t want=true", s.gpmAllowLegacyConnectOverride)
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
		if s.gpmManifestRequireHTTPS {
			t.Fatalf("gpmManifestRequireHTTPS=%t want=false", s.gpmManifestRequireHTTPS)
		}
		if s.gpmManifestRequireSignature {
			t.Fatalf("gpmManifestRequireSignature=%t want=false", s.gpmManifestRequireSignature)
		}
		if s.gpmManifestRequireHTTPSSource != "GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS" {
			t.Fatalf("gpmManifestRequireHTTPSSource=%q want=GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", s.gpmManifestRequireHTTPSSource)
		}
		if s.gpmManifestRequireSigSource != "TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE" {
			t.Fatalf("gpmManifestRequireSigSource=%q want=TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", s.gpmManifestRequireSigSource)
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

	t.Run("invalid script path fails safe", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", filepath.Join(t.TempDir(), "does-not-exist.sh"))
		s := New()
		if s.scriptPath != "" {
			t.Fatalf("scriptPath=%q want empty when configured script path is invalid", s.scriptPath)
		}
	})
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
	mustFlagValue(t, cmds[1], "--install-route", "1")
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
		mustFlagValue(t, cmds[1], "--path-profile", "1hop")
		mustFlagValue(t, cmds[1], "--session-reuse", "1")
		mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
		mustFlagValue(t, cmds[1], "--min-operators", "1")
		mustFlagValue(t, cmds[1], "--beta-profile", "0")
		mustFlagValue(t, cmds[1], "--prod-profile", "0")
		mustFlagValue(t, cmds[1], "--install-route", "0")
	})

	t.Run("one-hop install_route override and no preflight", func(t *testing.T) {
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
		mustFlagValue(t, cmds[0], "--install-route", "1")
	})
}

func TestHandleConnectThreeHopProdOverrides(t *testing.T) {
	svc, logPath := newFakeService(t, false)

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"bootstrap_directory":"https://dir.example:8081",
		"invite_key":"inv-test-3hop",
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
	mustFlagValue(t, cmds[1], "--path-profile", "3hop")
	mustFlagValue(t, cmds[1], "--session-reuse", "1")
	mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
	mustFlagValue(t, cmds[1], "--prod-profile", "1")
	mustFlagValue(t, cmds[1], "--beta-profile", "1")
	mustFlagValue(t, cmds[1], "--ready-timeout-sec", "66")
	mustFlagValue(t, cmds[1], "--install-route", "1")
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

	t.Run("manual overrides remain allowed when legacy override policy is enabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = false
		svc.gpmAllowLegacyConnectOverride = true

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
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
		mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir.example:8081")
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
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
			Token:          "gpm-connect-unregistered-session-token",
			WalletAddress:  "cosmos1connectunregistered",
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      time.Now().UTC(),
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
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
			Token:              "gpm-connect-session-token",
			WalletAddress:      "cosmos1connectsession",
			WalletProvider:     "keplr",
			Role:               "client",
			CreatedAt:          now,
			ExpiresAt:          now.Add(time.Hour),
			BootstrapDirectory: "https://dir.example:8081",
			InviteKey:          "wallet:cosmos1connectsession",
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
			Token:                "gpm-connect-session-failover-token",
			WalletAddress:        "cosmos1connectfailover",
			WalletProvider:       "keplr",
			Role:                 "client",
			CreatedAt:            now,
			ExpiresAt:            now.Add(time.Hour),
			BootstrapDirectory:   firstBootstrap,
			BootstrapDirectories: []string{firstBootstrap, secondBootstrap},
			InviteKey:            "wallet:cosmos1connectfailover",
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
			Token:                "gpm-connect-session-drift-token",
			WalletAddress:        "cosmos1connectdrift",
			WalletProvider:       "keplr",
			Role:                 "client",
			CreatedAt:            now,
			ExpiresAt:            now.Add(time.Hour),
			BootstrapDirectory:   "https://dir-revoked-primary.example:8081",
			BootstrapDirectories: []string{"https://dir-revoked-primary.example:8081", "https://dir-revoked-secondary.example:8081"},
			InviteKey:            "wallet:cosmos1connectdrift",
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
			Token:                "gpm-connect-session-partial-trust-token",
			WalletAddress:        "cosmos1connectpartialtrust",
			WalletProvider:       "keplr",
			Role:                 "client",
			CreatedAt:            now,
			ExpiresAt:            now.Add(time.Hour),
			BootstrapDirectory:   revokedBootstrap,
			BootstrapDirectories: []string{revokedBootstrap, trustedBootstrap},
			InviteKey:            "wallet:cosmos1connectpartialtrust",
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
			Token:              "gpm-connect-profile-conflict-token",
			WalletAddress:      "cosmos1profileconflict",
			WalletProvider:     "keplr",
			Role:               "client",
			CreatedAt:          time.Now().UTC(),
			ExpiresAt:          time.Now().UTC().Add(time.Hour),
			BootstrapDirectory: "https://dir.example:8081",
			InviteKey:          "wallet:cosmos1profileconflict",
			PathProfile:        "3hop",
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
			Token:              "gpm-connect-profile-inherit-token",
			WalletAddress:      "cosmos1profileinherit",
			WalletProvider:     "keplr",
			Role:               "client",
			CreatedAt:          time.Now().UTC(),
			ExpiresAt:          time.Now().UTC().Add(time.Hour),
			BootstrapDirectory: "https://dir.example:8081",
			InviteKey:          "wallet:cosmos1profileinherit",
			PathProfile:        "1hop",
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
			Token:              "gpm-connect-profile-compat-token",
			WalletAddress:      "cosmos1profilecompat",
			WalletProvider:     "keplr",
			Role:               "client",
			CreatedAt:          time.Now().UTC(),
			ExpiresAt:          time.Now().UTC().Add(time.Hour),
			BootstrapDirectory: "https://dir.example:8081",
			InviteKey:          "wallet:cosmos1profilecompat",
			PathProfile:        "",
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
}

func TestHandleSetProfileNormalizationAndValidation(t *testing.T) {
	svc, logPath := newFakeService(t, false)

	code, payload := callJSONHandler(t, svc.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":" FAST "}`)
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
	code, _ = callJSONHandler(t, svc2.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"bad"}`)
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
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"upstream",
			"branch":"release/v1",
			"allow_dirty":false
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

		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"--upload-pack=sh",
			"branch":"main"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid remote name") {
			t.Fatalf("error=%q want invalid remote message", got)
		}

		code, payload = callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"origin",
			"branch":"bad..branch"
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
		svc.authToken = "cfg-secret"
		svc.gpmConnectRequireSession = true
		svc.gpmAllowLegacyConnectOverride = true
		svc.gpmAuthVerifyRequireCommand = true
		svc.gpmAuthVerifyRequireMetadata = true
		svc.gpmAuthVerifyRequireWalletExt = true
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
		svc.commandTimeout = 150 * time.Second

		code, payload := callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer cfg-secret",
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
		if got, _ := configMap["allow_legacy_connect_override"].(bool); !got {
			t.Fatalf("allow_legacy_connect_override=%v want=true", configMap["allow_legacy_connect_override"])
		}
		if got, _ := configMap["connect_policy_mode"].(string); got != "production" {
			t.Fatalf("connect_policy_mode=%q want=%q", got, "production")
		}
		if got, _ := configMap["connect_policy_source"].(string); got != "GPM_PRODUCTION_MODE" {
			t.Fatalf("connect_policy_source=%q want=%q", got, "GPM_PRODUCTION_MODE")
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
		if got, _ := configMap["gpm_auth_verify_require_wallet_extension_source"].(bool); !got {
			t.Fatalf("gpm_auth_verify_require_wallet_extension_source=%v want=true", configMap["gpm_auth_verify_require_wallet_extension_source"])
		}
		if got, _ := configMap["gpm_auth_verify_require_wallet_extension_policy_source"].(string); got != "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE" {
			t.Fatalf("gpm_auth_verify_require_wallet_extension_policy_source=%q want=%q", got, "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE")
		}
		if got, _ := configMap["gpm_auth_verify_command_configured"].(bool); !got {
			t.Fatalf("gpm_auth_verify_command_configured=%v want=true", configMap["gpm_auth_verify_command_configured"])
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
		svc.authToken = "read-secret"

		code, payload := callJSONHandler(t, svc.handleConfig, http.MethodGet, "/v1/config", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("missing token status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "unauthorized" {
			t.Fatalf("error=%q want=unauthorized", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleConfig, http.MethodGet, "/v1/config", "", map[string]string{
			"Authorization": "Bearer read-secret",
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
		svc.authToken = "service-secret"
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
					"Authorization": "Bearer service-secret",
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
			Token:           "gpm-operator-pending-token",
			Role:            "operator",
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().UTC().Add(time.Hour),
			WalletAddress:   "cosmos1operatorpending",
			ChainOperatorID: "operator-pending-1",
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

	t.Run("operator role with approved application but missing session chain operator id rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:         "gpm-operator-approved-missing-session-chain-token",
			Role:          "operator",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
			WalletAddress: "cosmos1operatormissingsessionchain",
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
			Token:           "gpm-operator-approved-missing-approved-chain-token",
			Role:            "operator",
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().UTC().Add(time.Hour),
			WalletAddress:   "cosmos1operatormissingapprovedchain",
			ChainOperatorID: "operator-approved-missing-approved-chain-1",
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
			Token:           "gpm-operator-approved-mismatch-chain-token",
			Role:            "operator",
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().UTC().Add(time.Hour),
			WalletAddress:   "cosmos1operatormismatchchain",
			ChainOperatorID: "operator-approved-mismatch-a",
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
					Token:           "gpm-operator-token",
					Role:            "operator",
					CreatedAt:       time.Now().UTC(),
					ExpiresAt:       time.Now().UTC().Add(time.Hour),
					WalletAddress:   "cosmos1operator",
					ChainOperatorID: "operator-approved-1",
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
			Token:         "gpm-admin-token",
			Role:          "admin",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
			WalletAddress: "cosmos1admin",
		})

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

	t.Run("non-loopback rejects missing or invalid bearer token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = "secret-token"

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
		svc.authToken = "secret-token"

		code, payload := callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer secret-token",
		})
		if code != http.StatusOK {
			t.Fatalf("disconnect status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"2hop"}`, map[string]string{
			"Authorization": "Bearer secret-token",
		})
		if code != http.StatusOK {
			t.Fatalf("set_profile status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{}`, map[string]string{
			"Authorization": "Bearer secret-token",
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
		svc.authToken = "read-secret"
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
					"Authorization": "Bearer read-secret",
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
	code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{}`)
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
	if !got.installRoute {
		t.Fatalf("installRoute=%t want true", got.installRoute)
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

func TestIsLoopbackBindAddrRequiresLoopbackDNSResolution(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}

	if isLoopbackBindAddr("localhost:8095") {
		t.Fatal("expected localhost bind to be rejected when DNS resolves to non-loopback")
	}
}

func TestIsAllowedUnauthLoopbackOriginRequiresLoopbackDNSResolution(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	if !isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://localhost:8095") {
		t.Fatal("expected localhost origin to pass when DNS resolves to loopback")
	}

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.11")}}, nil
	}
	if isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://localhost:8095") {
		t.Fatal("expected localhost origin to be rejected when DNS resolves to non-loopback")
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

	verifyBody := `{"wallet_address":"cosmos1testwallet","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
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
}

func TestGPMAuthChallengeFailsClosedWhenChallengeStateSaturated(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	for i := 0; i < gpmChallengeMaxEntries; i++ {
		ok := svc.gpmState.putChallenge(gpmWalletChallenge{
			ChallengeID:    fmt.Sprintf("gpm-chal-seed-%d", i),
			WalletAddress:  "cosmos1challengefill",
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
		if signature != "signed-proof-value" {
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

	verifyBody := `{"wallet_address":"cosmos1customverifier","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
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

	verifyBody := `{"wallet_address":"cosmos1customreject","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
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
		SignaturePublicKey:     "04abc123",
		SignaturePublicKeyType: "secp256k1",
		SignatureSource:        "wallet_extension",
		ChainID:                "evm-11155111",
		SignatureEnvelope:      "envelope-v1",
	}

	challengeBody := `{"wallet_address":"cosmos1cmdmeta","wallet_provider":"keplr"}`
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
	expectedMetadata.SignedMessage = challengeMessage
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignatureMetadata("signed-proof-value", expectedMetadata, "bad-signature-metadata", 13)

	verifyBody := `{"wallet_address":"cosmos1cmdmeta","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value","signature_kind":"eip191","signature_public_key":"04abc123","signature_public_key_type":"secp256k1","signature_source":"wallet_extension","chain_id":"evm-11155111","signed_message":"` + challengeMessage + `","signature_envelope":"envelope-v1"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
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
		SignaturePublicKey:     "04legacyabc",
		SignaturePublicKeyType: "secp256k1",
		SignatureSource:        "wallet_extension",
		ChainID:                "evm-11155111",
		SignatureEnvelope:      "envelope-v1",
	}

	challengeBody := `{"wallet_address":"cosmos1cmdmetaalias","wallet_provider":"keplr"}`
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
	expectedMetadata.SignedMessage = challengeMessage
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignatureMetadata("signed-proof-value", expectedMetadata, "bad-signature-metadata", 13)

	verifyRequest := map[string]any{
		"wallet_address":     "cosmos1cmdmetaalias",
		"wallet_provider":    "keplr",
		"challenge_id":       challengeID,
		"signature":          "signed-proof-value",
		"signature_kind":     "eip191",
		"public_key":         "04legacyabc",
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
		SignaturePublicKey:     "04canonicalabc",
		SignaturePublicKeyType: "ed25519",
		SignatureSource:        "wallet_extension",
		ChainID:                "evm-11155111",
		SignatureEnvelope:      "envelope-v1",
	}

	challengeBody := `{"wallet_address":"cosmos1cmdmetaprefer","wallet_provider":"keplr"}`
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
	expectedMetadata.SignedMessage = challengeMessage
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignatureMetadata("signed-proof-value", expectedMetadata, "bad-signature-metadata", 13)

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1cmdmetaprefer",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 "signed-proof-value",
		"signature_kind":            "eip191",
		"signature_public_key":      "04canonicalabc",
		"public_key":                "04legacyignored",
		"signature_public_key_type": "ed25519",
		"public_key_type":           "secp256k1",
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

	challengeBody := `{"wallet_address":"cosmos1metaallow","wallet_provider":"keplr"}`
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

	verifyRequest := map[string]any{
		"wallet_address":            "cosmos1metaallow",
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 "signed-proof-value",
		"signature_kind":            "sign_arbitrary",
		"signature_public_key":      "edpk12345",
		"signature_public_key_type": "ed25519",
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

		verifyRequest := map[string]any{
			"wallet_address":   "cosmos1policymetadatapass",
			"wallet_provider":  "keplr",
			"challenge_id":     challengeID,
			"signature":        "signed-proof-value",
			"signature_kind":   "eip191",
			"signature_source": "manual",
			"signed_message":   challengeMessage,
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

		verifyRequest := map[string]any{
			"wallet_address":   "cosmos1policywalletsrcpass",
			"wallet_provider":  "keplr",
			"challenge_id":     challengeID,
			"signature":        "signed-proof-value",
			"signature_source": "wallet_extension",
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
	if !strings.Contains(errMsg, "bad-signature") {
		t.Fatalf("error=%q want verifier command output marker payload=%v", errMsg, payload)
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
		Token:          sessionToken,
		WalletAddress:  "cosmos1upgradeoperator",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
		Token:          token,
		WalletAddress:  "cosmos1registeredclient",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
			InviteKey:          "inv-0123456789abcdef012345",
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

		body := `{"wallet_address":"cosmos1walletonlystatus"}`
		code, payload := callJSONHandler(t, svc.handleGPMServerStatus, http.MethodPost, "/v1/gpm/onboarding/server/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		readiness := getReadiness(t, payload)
		if got, _ := readiness["wallet_address"].(string); got != "cosmos1walletonlystatus" {
			t.Fatalf("wallet_address=%q want=cosmos1walletonlystatus payload=%v", got, payload)
		}
		if got, _ := readiness["session_present"].(bool); got {
			t.Fatalf("session_present=%v want=false payload=%v", readiness["session_present"], payload)
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
		t.Setenv("EASY_NODE_SERVER_MODE", "")
		t.Setenv("CORE_ISSUER_URL", "")
		t.Setenv("ISSUER_URLS", "")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "")

		body := `{"wallet_address":"cosmos1diagbackcompat"}`
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
		t.Setenv("EASY_NODE_SERVER_MODE", "provider")
		t.Setenv("CORE_ISSUER_URL", "")
		t.Setenv("ISSUER_URLS", "")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "")

		body := `{"wallet_address":"cosmos1diagprovider"}`
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
		t.Setenv("EASY_NODE_SERVER_MODE", "authority")
		t.Setenv("CORE_ISSUER_URL", "https://authority.globalprivatemesh.example:8082")
		t.Setenv("ISSUER_URLS", "")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "")

		body := `{"wallet_address":"cosmos1diagauthority"}`
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
		t.Setenv("EASY_NODE_SERVER_MODE", "provider")
		t.Setenv("CORE_ISSUER_URL", "https://core.globalprivatemesh.example:8082")
		t.Setenv("ISSUER_URLS", "https://issuer-a.globalprivatemesh.example:8082,http://203.0.113.20:8082")
		t.Setenv("DIRECTORY_ISSUER_TRUST_URLS", "https://issuer-b.globalprivatemesh.example:8082,http://198.51.100.21:8082")

		body := `{"wallet_address":"cosmos1diagmixed"}`
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
			Token:          token,
			WalletAddress:  "cosmos1operatorlistadmin",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})
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
			Token:          "gpm-admin-approval-token",
			WalletAddress:  "cosmos1adminapprover",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      time.Now().UTC(),
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		})
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
			Token:          token,
			WalletAddress:  "cosmos1decisionadmin",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})
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
			Token:          token,
			WalletAddress:  "cosmos1concurrencyadmin",
			WalletProvider: "keplr",
			Role:           "admin",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		})
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
		Token:          token,
		WalletAddress:  "cosmos1registeredclientmismatch",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
		Token:          token,
		WalletAddress:  "cosmos1httppinnedmanifest",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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

	sessions, _ := svc.gpmState.snapshotPersistent(time.Now().UTC())
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
		Token:          token,
		WalletAddress:  "cosmos1cachefallback",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
		Token:          token,
		WalletAddress:  "cosmos1cachehmacevidence",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
	svc.gpmManifestTrustPolicyMode = "production"
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
		Token:          token,
		WalletAddress:  "cosmos1cachemissingkey",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
		Token:          token,
		WalletAddress:  "cosmos1cachehmacverified",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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
		Token:          token,
		WalletAddress:  "cosmos1cachemismatch",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
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

	loaded := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	loaded.loadGPMStateBestEffort()

	session, ok := loaded.gpmState.getSession("persist-token", now)
	if !ok {
		t.Fatal("expected persisted session to be loaded")
	}
	if session.Role != "operator" {
		t.Fatalf("loaded role=%q want=operator", session.Role)
	}
	if session.ChainOperatorID != "operator-persist-1" {
		t.Fatalf("loaded chain_operator_id=%q want=operator-persist-1", session.ChainOperatorID)
	}
	if len(session.BootstrapDirectories) != 2 {
		t.Fatalf("loaded bootstrap_directories=%v want two directories", session.BootstrapDirectories)
	}
	if session.BootstrapDirectories[0] != "https://directory.gpm.example:8081" || session.BootstrapDirectories[1] != "https://directory-backup.gpm.example:8081" {
		t.Fatalf("loaded bootstrap_directories=%v", session.BootstrapDirectories)
	}

	operator, ok := loaded.gpmState.getOperator("cosmos1persist")
	if !ok {
		t.Fatal("expected persisted operator application to be loaded")
	}
	if operator.Status != "approved" {
		t.Fatalf("loaded operator status=%q want=approved", operator.Status)
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?limit=1", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?event=AuTh_VeRiFiEd", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?wallet_address=COSMOS1WALLETA", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?limit=2&offset=1&order=desc", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?order=sideways", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?wallet_address=bad!", "")
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

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent", "")
	if code != http.StatusInternalServerError {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "maximum readable size") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}
