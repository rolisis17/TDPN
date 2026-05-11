package securehttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"privacynode/internal/fileperm"
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

func TestRequireClientCertConfigured(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "unset defaults true", want: true},
		{name: "one enables", raw: "1", want: true},
		{name: "zero disables", raw: "0", want: false},
		{name: "false string stays enabled for legacy compatibility", raw: "false", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MTLS_REQUIRE_CLIENT_CERT", tc.raw)
			if got := RequireClientCertConfigured(); got != tc.want {
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

func TestValidateMTLSChecksCertificatePairsChainsAndUsages(t *testing.T) {
	tmpDir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	serverCertPEM, serverKeyPEM := newTestLeaf(t, ca, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertPEM, clientKeyPEM := newTestLeaf(t, ca, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	serverCertFile := writeMTLSFile(t, tmpDir, "server.crt", serverCertPEM, false)
	serverKeyFile := writeMTLSFile(t, tmpDir, "server.key", serverKeyPEM, true)
	clientCertFile := writeMTLSFile(t, tmpDir, "client.crt", clientCertPEM, false)
	clientKeyFile := writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true)
	caFile := writeMTLSFile(t, tmpDir, "ca.crt", ca.certPEM, false)

	setMTLSEnv(t, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile, caFile)
	if err := Validate(); err != nil {
		t.Fatalf("expected valid mTLS material, got %v", err)
	}
}

func TestValidateMTLSAcceptsIntermediateCertificateChains(t *testing.T) {
	tmpDir := t.TempDir()
	rootCA := newTestCA(t, "root-ca")
	intermediateCA := newTestIntermediateCA(t, rootCA, "intermediate-ca")
	serverCertPEM, serverKeyPEM := newTestLeaf(t, intermediateCA, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertPEM, clientKeyPEM := newTestLeaf(t, intermediateCA, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server.crt", appendPEM(serverCertPEM, intermediateCA.certPEM), false),
		writeMTLSFile(t, tmpDir, "server.key", serverKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client.crt", appendPEM(clientCertPEM, intermediateCA.certPEM), false),
		writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca.crt", rootCA.certPEM, false),
	)

	if err := Validate(); err != nil {
		t.Fatalf("expected valid intermediate mTLS chain, got %v", err)
	}
}

func TestValidateMTLSChecksConfiguredServerName(t *testing.T) {
	tmpDir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	serverCertPEM, serverKeyPEM := newTestLeaf(t, ca, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertPEM, clientKeyPEM := newTestLeaf(t, ca, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server.crt", serverCertPEM, false),
		writeMTLSFile(t, tmpDir, "server.key", serverKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client.crt", clientCertPEM, false),
		writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca.crt", ca.certPEM, false),
	)
	t.Setenv("MTLS_SERVER_NAME", "expected.example")

	err := Validate()
	if err == nil {
		t.Fatal("expected server name mismatch to fail")
	}
	if !strings.Contains(err.Error(), "verify mTLS server certificate chain") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMTLSRejectsServerKeyMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	serverCertPEM, _ := newTestLeaf(t, ca, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	_, otherKeyPEM := newTestLeaf(t, ca, "other", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertPEM, clientKeyPEM := newTestLeaf(t, ca, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server.crt", serverCertPEM, false),
		writeMTLSFile(t, tmpDir, "server.key", otherKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client.crt", clientCertPEM, false),
		writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca.crt", ca.certPEM, false),
	)

	err := Validate()
	if err == nil {
		t.Fatal("expected server key mismatch to fail")
	}
	if !strings.Contains(err.Error(), "load mTLS server cert/key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMTLSRejectsUntrustedServerChain(t *testing.T) {
	tmpDir := t.TempDir()
	trustedCA := newTestCA(t, "trusted-ca")
	otherCA := newTestCA(t, "other-ca")
	serverCertPEM, serverKeyPEM := newTestLeaf(t, otherCA, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientCertPEM, clientKeyPEM := newTestLeaf(t, trustedCA, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server.crt", serverCertPEM, false),
		writeMTLSFile(t, tmpDir, "server.key", serverKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client.crt", clientCertPEM, false),
		writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca.crt", trustedCA.certPEM, false),
	)

	err := Validate()
	if err == nil {
		t.Fatal("expected untrusted server chain to fail")
	}
	if !strings.Contains(err.Error(), "verify mTLS server certificate chain") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMTLSRejectsWrongExtendedKeyUsage(t *testing.T) {
	tmpDir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	serverCertPEM, serverKeyPEM := newTestLeaf(t, ca, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	clientCertPEM, clientKeyPEM := newTestLeaf(t, ca, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server.crt", serverCertPEM, false),
		writeMTLSFile(t, tmpDir, "server.key", serverKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client.crt", clientCertPEM, false),
		writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca.crt", ca.certPEM, false),
	)

	err := Validate()
	if err == nil {
		t.Fatal("expected wrong server EKU to fail")
	}
	if !strings.Contains(err.Error(), "mTLS server certificate missing serverAuth usage") {
		t.Fatalf("unexpected error: %v", err)
	}

	serverCertPEM, serverKeyPEM = newTestLeaf(t, ca, "server-ok", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server-ok.crt", serverCertPEM, false),
		writeMTLSFile(t, tmpDir, "server-ok.key", serverKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client-server-only.crt", clientCertPEM, false),
		writeMTLSFile(t, tmpDir, "client-server-only.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca2.crt", ca.certPEM, false),
	)
	err = Validate()
	if err == nil {
		t.Fatal("expected wrong client EKU to fail")
	}
	if !strings.Contains(err.Error(), "mTLS client certificate missing clientAuth usage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMTLSRejectsMissingExtendedKeyUsage(t *testing.T) {
	tmpDir := t.TempDir()
	ca := newTestCA(t, "test-ca")
	serverCertPEM, serverKeyPEM := newTestLeaf(t, ca, "server", nil)
	clientCertPEM, clientKeyPEM := newTestLeaf(t, ca, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	setMTLSEnv(t,
		writeMTLSFile(t, tmpDir, "server.crt", serverCertPEM, false),
		writeMTLSFile(t, tmpDir, "server.key", serverKeyPEM, true),
		writeMTLSFile(t, tmpDir, "client.crt", clientCertPEM, false),
		writeMTLSFile(t, tmpDir, "client.key", clientKeyPEM, true),
		writeMTLSFile(t, tmpDir, "ca.crt", ca.certPEM, false),
	)

	err := Validate()
	if err == nil {
		t.Fatal("expected missing server EKU to fail")
	}
	if !strings.Contains(err.Error(), "mTLS server certificate missing serverAuth usage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type testCA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().Add(-time.Hour)
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	return testCA{
		cert: cert,
		key:  key,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
	}
}

func newTestIntermediateCA(t *testing.T, parent testCA, cn string) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate CA key: %v", err)
	}
	now := time.Now().Add(-time.Hour)
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("create intermediate CA certificate: %v", err)
	}
	return testCA{
		cert: cert,
		key:  key,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
	}
}

func newTestLeaf(t *testing.T, ca testCA, cn string, usages []x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now().Add(-time.Hour)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func appendPEM(blocks ...[]byte) []byte {
	var out []byte
	for _, block := range blocks {
		out = append(out, block...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	return out
}

func writeMTLSFile(t *testing.T, dir, name string, contents []byte, secret bool) string {
	t.Helper()
	path := filepath.Join(dir, name)
	perm := os.FileMode(0o644)
	if secret {
		perm = 0o600
	}
	if err := os.WriteFile(path, contents, perm); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if secret {
		if err := fileperm.RestrictOwnerOnly(path); err != nil {
			t.Fatalf("restrict %s: %v", name, err)
		}
	}
	return path
}

func setMTLSEnv(t *testing.T, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile, caFile string) {
	t.Helper()
	t.Setenv("MTLS_ENABLE", "1")
	t.Setenv("MTLS_SERVER_CERT_FILE", serverCertFile)
	t.Setenv("MTLS_SERVER_KEY_FILE", serverKeyFile)
	t.Setenv("MTLS_CLIENT_CERT_FILE", clientCertFile)
	t.Setenv("MTLS_CLIENT_KEY_FILE", clientKeyFile)
	t.Setenv("MTLS_CA_FILE", caFile)
	t.Setenv("MTLS_MIN_VERSION", "1.3")
}
