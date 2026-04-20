package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestApplyConfigFileV1OneHop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "easy_mode_config_v1.conf")
	if err := os.WriteFile(path, []byte(
		"EASY_MODE_CONFIG_VERSION=1\n"+
			"SIMPLE_CLIENT_PROFILE_DEFAULT=1hop\n"+
			"SIMPLE_CLIENT_INTERFACE=wgvpn9\n"+
			"SIMPLE_CLIENT_RUN_PREFLIGHT=0\n"+
			"SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=auto\n",
	), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CLIENT_REQUIRE_DISTINCT_OPERATORS", "")
	t.Setenv("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "")
	t.Setenv("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK", "")
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "")
	t.Setenv("CLIENT_SESSION_REUSE", "")
	t.Setenv("CLIENT_STICKY_PAIR_SEC", "")
	t.Setenv("CLIENT_PATH_PROFILE", "")
	t.Setenv("CLIENT_WG_INTERFACE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")

	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("CLIENT_REQUIRE_DISTINCT_OPERATORS"); got != "0" {
		t.Fatalf("CLIENT_REQUIRE_DISTINCT_OPERATORS=%q want 0", got)
	}
	if got := os.Getenv("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK"); got != "1" {
		t.Fatalf("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=%q want 1", got)
	}
	if got := os.Getenv("CLIENT_FORCE_DIRECT_EXIT"); got != "1" {
		t.Fatalf("CLIENT_FORCE_DIRECT_EXIT=%q want 1", got)
	}
	if got := os.Getenv("CLIENT_SESSION_REUSE"); got != "1" {
		t.Fatalf("CLIENT_SESSION_REUSE=%q want 1", got)
	}
	if got := os.Getenv("CLIENT_STICKY_PAIR_SEC"); got != "300" {
		t.Fatalf("CLIENT_STICKY_PAIR_SEC=%q want 300", got)
	}
	if got := os.Getenv("CLIENT_PATH_PROFILE"); got != "1hop" {
		t.Fatalf("CLIENT_PATH_PROFILE=%q want 1hop", got)
	}
	if got := os.Getenv("CLIENT_WG_INTERFACE"); got != "wgvpn9" {
		t.Fatalf("CLIENT_WG_INTERFACE=%q want wgvpn9", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE"); got != "1hop" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE=%q want 1hop", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_INTERFACE"); got != "wgvpn9" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_INTERFACE=%q want wgvpn9", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT"); got != "0" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT=%q want 0", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT"); got != "auto" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT=%q want auto", got)
	}
}

func TestApplyConfigFileV1RespectsExistingEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "easy_mode_config_v1.conf")
	if err := os.WriteFile(path, []byte(
		"EASY_MODE_CONFIG_VERSION=1\n"+
			"SIMPLE_CLIENT_PROFILE_DEFAULT=3hop\n"+
			"SIMPLE_CLIENT_RUN_PREFLIGHT=0\n"+
			"SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=1\n",
	), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "0")
	t.Setenv("CLIENT_SESSION_REUSE", "0")
	t.Setenv("CLIENT_PATH_PROFILE", "2hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "2hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "1")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "0")
	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY"); got != "0" {
		t.Fatalf("expected existing env to be preserved, got %q", got)
	}
	if got := os.Getenv("CLIENT_SESSION_REUSE"); got != "0" {
		t.Fatalf("expected existing session reuse env to be preserved, got %q", got)
	}
	if got := os.Getenv("CLIENT_PATH_PROFILE"); got != "2hop" {
		t.Fatalf("expected existing path profile env to be preserved, got %q", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE"); got != "2hop" {
		t.Fatalf("expected existing localapi path env to be preserved, got %q", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT"); got != "1" {
		t.Fatalf("expected existing localapi preflight env to be preserved, got %q", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT"); got != "0" {
		t.Fatalf("expected existing localapi prod env to be preserved, got %q", got)
	}
}

func TestApplyConfigFileGenericEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "generic.env")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("FOO", "")
	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("FOO"); got != "bar" {
		t.Fatalf("FOO=%q want bar", got)
	}
}

func TestApplyConfigFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.env")
	if err := os.WriteFile(target, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write target config: %v", err)
	}
	link := filepath.Join(dir, "config.env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported in test environment: %v", err)
	}
	err := applyConfigFile(link)
	if err == nil {
		t.Fatalf("expected symlink config file to be rejected")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestApplyConfigFileRejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.env")
	payload := strings.Repeat("A", int(configFileMaxBytes)+1)
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	err := applyConfigFile(path)
	if err == nil {
		t.Fatalf("expected oversize config file to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected max-size error, got %v", err)
	}
}

func TestApplyConfigFileRejectsOverlongLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "longline.env")
	content := "FOO=" + strings.Repeat("x", configFileLineMaxBytes+1) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	err := applyConfigFile(path)
	if err == nil {
		t.Fatalf("expected overlong config line to be rejected")
	}
	if !strings.Contains(err.Error(), "line exceeds") {
		t.Fatalf("expected line-length error, got %v", err)
	}
}

func TestApplyConfigFileGenericEnvBlocksDangerousLocalAPIKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "generic.env")
	content := strings.Join([]string{
		"FOO=bar",
		"LOCAL_CONTROL_API_AUTH_TOKEN=secret-token",
		"LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1",
		"LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP=1",
		"LOCAL_CONTROL_API_SCRIPT=/tmp/evil.sh",
		"LOCAL_CONTROL_API_RUNNER=/tmp/evil-runner",
		"LOCAL_CONTROL_API_ADDR=0.0.0.0:9999",
		"LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND=echo status",
		"LOCAL_CONTROL_API_SERVICE_START_COMMAND=echo start",
		"LOCAL_CONTROL_API_SERVICE_STOP_COMMAND=echo stop",
		"LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND=echo restart",
		"MTLS_ALLOW_PROXY_FROM_ENV=1",
		"COSMOS_ADAPTER_ALLOW_PROXY_FROM_ENV=1",
		"COSMOS_ADAPTER_ALLOW_DANGEROUS_PRIVATE_ENDPOINT=1",
		"CLIENT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1",
		"ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1",
		"EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1",
		"DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1",
		"WG_ALLOW_UNTRUSTED_BINARY_PATH=1",
		"CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP=1",
		"CLIENT_REQUIRE_HTTPS_CONTROL_URL=0",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("FOO", "")
	t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", "")
	t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "")
	t.Setenv("LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP", "")
	t.Setenv("LOCAL_CONTROL_API_SCRIPT", "")
	t.Setenv("LOCAL_CONTROL_API_RUNNER", "")
	t.Setenv("LOCAL_CONTROL_API_ADDR", "")
	t.Setenv("LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND", "")
	t.Setenv("LOCAL_CONTROL_API_SERVICE_START_COMMAND", "")
	t.Setenv("LOCAL_CONTROL_API_SERVICE_STOP_COMMAND", "")
	t.Setenv("LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND", "")
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "")
	t.Setenv("COSMOS_ADAPTER_ALLOW_PROXY_FROM_ENV", "")
	t.Setenv("COSMOS_ADAPTER_ALLOW_DANGEROUS_PRIVATE_ENDPOINT", "")
	t.Setenv("CLIENT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS", "")
	t.Setenv("ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS", "")
	t.Setenv("EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS", "")
	t.Setenv("DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS", "")
	t.Setenv("WG_ALLOW_UNTRUSTED_BINARY_PATH", "")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	t.Setenv("CLIENT_REQUIRE_HTTPS_CONTROL_URL", "")
	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("FOO"); got != "bar" {
		t.Fatalf("FOO=%q want bar", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_AUTH_TOKEN"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_AUTH_TOKEN=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_SCRIPT"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_SCRIPT=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_RUNNER"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_RUNNER=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_ADDR"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_ADDR=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_SERVICE_START_COMMAND"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_SERVICE_START_COMMAND=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_SERVICE_STOP_COMMAND"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_SERVICE_STOP_COMMAND=%q want empty", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND"); got != "" {
		t.Fatalf("LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND=%q want empty", got)
	}
	if got := os.Getenv("MTLS_ALLOW_PROXY_FROM_ENV"); got != "" {
		t.Fatalf("MTLS_ALLOW_PROXY_FROM_ENV=%q want empty", got)
	}
	if got := os.Getenv("COSMOS_ADAPTER_ALLOW_PROXY_FROM_ENV"); got != "" {
		t.Fatalf("COSMOS_ADAPTER_ALLOW_PROXY_FROM_ENV=%q want empty", got)
	}
	if got := os.Getenv("COSMOS_ADAPTER_ALLOW_DANGEROUS_PRIVATE_ENDPOINT"); got != "" {
		t.Fatalf("COSMOS_ADAPTER_ALLOW_DANGEROUS_PRIVATE_ENDPOINT=%q want empty", got)
	}
	if got := os.Getenv("CLIENT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"); got != "" {
		t.Fatalf("CLIENT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=%q want empty", got)
	}
	if got := os.Getenv("ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"); got != "" {
		t.Fatalf("ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=%q want empty", got)
	}
	if got := os.Getenv("EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"); got != "" {
		t.Fatalf("EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=%q want empty", got)
	}
	if got := os.Getenv("DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"); got != "" {
		t.Fatalf("DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=%q want empty", got)
	}
	if got := os.Getenv("WG_ALLOW_UNTRUSTED_BINARY_PATH"); got != "" {
		t.Fatalf("WG_ALLOW_UNTRUSTED_BINARY_PATH=%q want empty", got)
	}
	if got := os.Getenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP"); got != "" {
		t.Fatalf("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP=%q want empty", got)
	}
	if got := os.Getenv("CLIENT_REQUIRE_HTTPS_CONTROL_URL"); got != "" {
		t.Fatalf("CLIENT_REQUIRE_HTTPS_CONTROL_URL=%q want empty", got)
	}
}

func TestApplyConfigFileRejectsTooManyEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many.env")
	var b strings.Builder
	for i := 0; i < configFileMaxEntries+1; i++ {
		b.WriteString(fmt.Sprintf("KEY_%d=%d\n", i, i))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	err := applyConfigFile(path)
	if err == nil {
		t.Fatalf("expected too-many-entries validation error")
	}
	if !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("expected too-many-entries error, got %v", err)
	}
}

func TestApplyConfigFileIgnoresUnsafeEnvKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unsafe-keys.env")
	content := strings.Join([]string{
		"SAFE_KEY=ok",
		"1BAD_KEY=bad",
		"BAD-KEY=bad",
		"BAD.KEY=bad",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("SAFE_KEY", "")
	t.Setenv("1BAD_KEY", "")
	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("SAFE_KEY"); got != "ok" {
		t.Fatalf("SAFE_KEY=%q want ok", got)
	}
	if got := os.Getenv("1BAD_KEY"); got != "" {
		t.Fatalf("1BAD_KEY=%q want empty", got)
	}
}

func TestIsSafeConfigEnvKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{key: "FOO", want: true},
		{key: "_FOO1", want: true},
		{key: "1FOO", want: false},
		{key: "FOO-BAR", want: false},
		{key: "FOO.BAR", want: false},
		{key: " ", want: false},
		{key: strings.Repeat("A", configFileMaxKeyBytes+1), want: false},
	}
	for _, tc := range tests {
		t.Run(strconv.Quote(tc.key), func(t *testing.T) {
			if got := isSafeConfigEnvKey(tc.key); got != tc.want {
				t.Fatalf("isSafeConfigEnvKey(%q)=%v want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestNormalizeConfigV1PathProfileAliasContract(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "1hop", want: "1hop"},
		{in: "2hop", want: "2hop"},
		{in: "3hop", want: "3hop"},
		{in: "speed-1hop", want: "1hop"},
		{in: "speed", want: "2hop"},
		{in: "fast", want: "2hop"},
		{in: "balanced", want: "2hop"},
		{in: "private", want: "3hop"},
		{in: "privacy", want: "3hop"},
		{in: "unknown", want: "2hop"},
	}
	for _, tc := range tests {
		if got := normalizeConfigV1PathProfile(tc.in); got != tc.want {
			t.Fatalf("normalizeConfigV1PathProfile(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}
