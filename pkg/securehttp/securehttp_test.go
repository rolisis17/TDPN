package securehttp

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInsecureSkipVerifyConfigured(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		want  bool
		unset bool
	}{
		{name: "unset defaults false", unset: true, want: false},
		{name: "one enables", raw: "1", want: true},
		{name: "true enables", raw: "true", want: true},
		{name: "non-bool numeric treated as default false", raw: "2", want: false},
		{name: "zero disables", raw: "0", want: false},
		{name: "false disables", raw: "false", want: false},
		{name: "invalid treated as default false", raw: "not-a-bool", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unset {
				t.Setenv("MTLS_INSECURE_SKIP_VERIFY", "")
			} else {
				t.Setenv("MTLS_INSECURE_SKIP_VERIFY", tc.raw)
			}
			if got := InsecureSkipVerifyConfigured(); got != tc.want {
				t.Fatalf("expected %t for %q, got %t", tc.want, tc.raw, got)
			}
		})
	}
}

func TestNewClientDisablesRedirectFollowingByDefault(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "")

	client, err := NewClient(2 * time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be configured")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if got := client.CheckRedirect(req, nil); !errors.Is(got, http.ErrUseLastResponse) {
		t.Fatalf("expected ErrUseLastResponse, got %v", got)
	}
}

func TestNewClientDisablesProxyFromEnvironmentByDefault(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "")
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18080")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18080")

	client, err := NewClient(2 * time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected proxy function to be nil by default")
	}
}

func TestNewClientAllowsProxyFromEnvironmentWithExplicitOverride(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "")
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "1")

	client, err := NewClient(2 * time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.Proxy == nil {
		t.Fatal("expected proxy function to be configured when override is enabled")
	}
}

func TestReadMTLSFileStrictRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.pem")
	if err := os.WriteFile(target, []byte("pem"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(tmpDir, "link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	_, err := readMTLSFileStrict(link, "MTLS_CLIENT_KEY_FILE", true, 1024)
	if err == nil {
		t.Fatalf("expected symlink rejection error")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadMTLSFileStrictRejectsBroadPermissionsForOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not authoritative on Windows")
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("pem"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := readMTLSFileStrict(path, "MTLS_CLIENT_KEY_FILE", true, 1024)
	if err == nil {
		t.Fatalf("expected permission validation error")
	}
	if !strings.Contains(err.Error(), "must not grant group/other permissions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadMTLSFileStrictRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := readMTLSFileStrict(path, "MTLS_CA_FILE", false, 4)
	if err == nil {
		t.Fatalf("expected max-size validation error")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("unexpected error: %v", err)
	}
}
