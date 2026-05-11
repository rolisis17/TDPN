package securehttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"privacynode/internal/fileperm"
)

const (
	mtlsMaxCertFileBytes = int64(1 << 20) // 1 MiB
	mtlsMaxKeyFileBytes  = int64(1 << 20) // 1 MiB
	mtlsMaxCAFileBytes   = int64(1 << 20) // 1 MiB
)

func Enabled() bool {
	return strings.TrimSpace(os.Getenv("MTLS_ENABLE")) == "1"
}

func InsecureSkipVerifyConfigured() bool {
	return boolEnv("MTLS_INSECURE_SKIP_VERIFY", false)
}

func RequireClientCertConfigured() bool {
	raw := strings.TrimSpace(os.Getenv("MTLS_REQUIRE_CLIENT_CERT"))
	return raw == "" || raw != "0"
}

func Validate() error {
	_, err := loadConfig()
	return err
}

func NewClient(timeout time.Duration) (*http.Client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	checkRedirect := func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	var clientTLS *tls.Config
	if cfg.enabled {
		clientTLS = &tls.Config{
			MinVersion:         cfg.minVersion,
			InsecureSkipVerify: cfg.insecureSkipVerify,
			RootCAs:            cfg.caPool,
			Certificates:       []tls.Certificate{cfg.clientCert},
		}
		if cfg.serverName != "" {
			clientTLS.ServerName = cfg.serverName
		}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       clientTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if boolEnv("MTLS_ALLOW_PROXY_FROM_ENV", false) {
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: checkRedirect}, nil
}

func ListenAndServe(srv *http.Server) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if !cfg.enabled {
		return srv.ListenAndServe()
	}
	tlsCfg := &tls.Config{
		MinVersion: cfg.minVersion,
		ClientCAs:  cfg.caPool,
	}
	if cfg.requireClientCert {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if srv.TLSConfig != nil {
		merged := srv.TLSConfig.Clone()
		merged.MinVersion = maxTLSVersion(merged.MinVersion, tlsCfg.MinVersion)
		if tlsCfg.ClientCAs != nil {
			merged.ClientCAs = tlsCfg.ClientCAs
		}
		if tlsCfg.ClientAuth != 0 {
			merged.ClientAuth = tlsCfg.ClientAuth
		}
		srv.TLSConfig = merged
	} else {
		srv.TLSConfig = tlsCfg
	}
	return srv.ListenAndServeTLS(cfg.serverCertFile, cfg.serverKeyFile)
}

type runtimeConfig struct {
	enabled            bool
	serverCertFile     string
	serverKeyFile      string
	clientCert         tls.Certificate
	caPool             *x509.CertPool
	requireClientCert  bool
	insecureSkipVerify bool
	serverName         string
	minVersion         uint16
}

func loadConfig() (runtimeConfig, error) {
	cfg := runtimeConfig{enabled: Enabled()}
	if !cfg.enabled {
		return cfg, nil
	}
	cfg.serverCertFile = firstNonEmpty(
		strings.TrimSpace(os.Getenv("MTLS_SERVER_CERT_FILE")),
		strings.TrimSpace(os.Getenv("MTLS_CERT_FILE")),
	)
	cfg.serverKeyFile = firstNonEmpty(
		strings.TrimSpace(os.Getenv("MTLS_SERVER_KEY_FILE")),
		strings.TrimSpace(os.Getenv("MTLS_KEY_FILE")),
	)
	clientCertFile := firstNonEmpty(
		strings.TrimSpace(os.Getenv("MTLS_CLIENT_CERT_FILE")),
		strings.TrimSpace(os.Getenv("MTLS_CERT_FILE")),
	)
	clientKeyFile := firstNonEmpty(
		strings.TrimSpace(os.Getenv("MTLS_CLIENT_KEY_FILE")),
		strings.TrimSpace(os.Getenv("MTLS_KEY_FILE")),
	)
	caFile := strings.TrimSpace(os.Getenv("MTLS_CA_FILE"))
	if cfg.serverCertFile == "" || cfg.serverKeyFile == "" || clientCertFile == "" || clientKeyFile == "" || caFile == "" {
		return runtimeConfig{}, fmt.Errorf("MTLS_ENABLE=1 requires cert/key/ca env files")
	}
	serverName := strings.TrimSpace(os.Getenv("MTLS_SERVER_NAME"))
	cfg.serverName = serverName

	requireClientCert := true
	if raw := strings.TrimSpace(os.Getenv("MTLS_REQUIRE_CLIENT_CERT")); raw != "" {
		requireClientCert = raw != "0"
	}
	cfg.requireClientCert = requireClientCert
	cfg.insecureSkipVerify = InsecureSkipVerifyConfigured()

	var minVersion uint16 = tls.VersionTLS13
	if raw := strings.TrimSpace(os.Getenv("MTLS_MIN_VERSION")); raw != "" {
		switch raw {
		case "1.2":
			minVersion = tls.VersionTLS12
		case "1.3":
			minVersion = tls.VersionTLS13
		default:
			return runtimeConfig{}, fmt.Errorf("invalid MTLS_MIN_VERSION=%s", raw)
		}
	}
	cfg.minVersion = minVersion

	serverCertPEM, err := readMTLSFileStrict(cfg.serverCertFile, "MTLS_SERVER_CERT_FILE", false, mtlsMaxCertFileBytes)
	if err != nil {
		return runtimeConfig{}, err
	}
	serverKeyPEM, err := readMTLSFileStrict(cfg.serverKeyFile, "MTLS_SERVER_KEY_FILE", true, mtlsMaxKeyFileBytes)
	if err != nil {
		return runtimeConfig{}, err
	}
	clientCertPEM, err := readMTLSFileStrict(clientCertFile, "MTLS_CLIENT_CERT_FILE", false, mtlsMaxCertFileBytes)
	if err != nil {
		return runtimeConfig{}, err
	}
	clientKeyPEM, err := readMTLSFileStrict(clientKeyFile, "MTLS_CLIENT_KEY_FILE", true, mtlsMaxKeyFileBytes)
	if err != nil {
		return runtimeConfig{}, err
	}
	caPEM, err := readMTLSFileStrict(caFile, "MTLS_CA_FILE", false, mtlsMaxCAFileBytes)
	if err != nil {
		return runtimeConfig{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return runtimeConfig{}, fmt.Errorf("invalid MTLS_CA_FILE")
	}
	cfg.caPool = pool

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("load mTLS server cert/key: %w", err)
	}
	serverLeaf, serverIntermediates, err := certificateChain(serverCert, "mTLS server certificate")
	if err != nil {
		return runtimeConfig{}, err
	}
	if err := verifyCertificateForUsage(serverLeaf, serverIntermediates, pool, x509.ExtKeyUsageServerAuth, cfg.serverName, "mTLS server certificate"); err != nil {
		return runtimeConfig{}, err
	}

	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("load mTLS client cert/key: %w", err)
	}
	clientLeaf, clientIntermediates, err := certificateChain(cert, "mTLS client certificate")
	if err != nil {
		return runtimeConfig{}, err
	}
	if err := verifyCertificateForUsage(clientLeaf, clientIntermediates, pool, x509.ExtKeyUsageClientAuth, "", "mTLS client certificate"); err != nil {
		return runtimeConfig{}, err
	}
	cfg.clientCert = cert

	return cfg, nil
}

func certificateChain(cert tls.Certificate, label string) (*x509.Certificate, *x509.CertPool, error) {
	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("%s has no leaf certificate", label)
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", label, err)
		}
	}
	intermediates := x509.NewCertPool()
	for i, raw := range cert.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s intermediate %d: %w", label, i+1, err)
		}
		intermediates.AddCert(intermediate)
	}
	return leaf, intermediates, nil
}

func verifyCertificateForUsage(cert *x509.Certificate, intermediates *x509.CertPool, roots *x509.CertPool, usage x509.ExtKeyUsage, dnsName string, label string) error {
	if cert == nil {
		return fmt.Errorf("%s is required", label)
	}
	if !certificateAllowsUsage(cert, usage) {
		return fmt.Errorf("%s missing %s usage", label, extKeyUsageName(usage))
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       dnsName,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}); err != nil {
		return fmt.Errorf("verify %s chain: %w", label, err)
	}
	return nil
}

func certificateAllowsUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, certUsage := range cert.ExtKeyUsage {
		if certUsage == usage || certUsage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func extKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	default:
		return fmt.Sprintf("extendedKeyUsage(%d)", usage)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func maxTLSVersion(a uint16, b uint16) uint16 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a >= b {
		return a
	}
	return b
}

func readMTLSFileStrict(path string, label string, ownerOnly bool, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%s is required", label)
	}
	linfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink", label)
	}
	if !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer f.Close()
	finfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open %s: %w", label, err)
	}
	if !os.SameFile(linfo, finfo) {
		return nil, fmt.Errorf("%s changed during open", label)
	}
	if ownerOnly {
		if err := fileperm.ValidateOwnerOnly(path, finfo); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
	}
	if maxBytes > 0 && finfo.Size() > maxBytes {
		return nil, fmt.Errorf("%s exceeds max size %d bytes", label, maxBytes)
	}
	reader := io.Reader(f)
	if maxBytes > 0 {
		reader = io.LimitReader(f, maxBytes+1)
	}
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds max size %d bytes", label, maxBytes)
	}
	return b, nil
}

func boolEnv(name string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	if raw == "1" || strings.EqualFold(raw, "true") {
		return true
	}
	if raw == "0" || strings.EqualFold(raw, "false") {
		return false
	}
	return def
}
