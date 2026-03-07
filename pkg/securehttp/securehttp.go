package securehttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func Enabled() bool {
	return strings.TrimSpace(os.Getenv("MTLS_ENABLE")) == "1"
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
	if !cfg.enabled {
		return &http.Client{Timeout: timeout}, nil
	}
	clientTLS := &tls.Config{
		MinVersion:         cfg.minVersion,
		InsecureSkipVerify: cfg.insecureSkipVerify,
		RootCAs:            cfg.caPool,
		Certificates:       []tls.Certificate{cfg.clientCert},
	}
	if cfg.serverName != "" {
		clientTLS.ServerName = cfg.serverName
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       clientTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
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
	cfg.insecureSkipVerify = strings.TrimSpace(os.Getenv("MTLS_INSECURE_SKIP_VERIFY")) == "1"

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

	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("load mTLS client cert/key: %w", err)
	}
	cfg.clientCert = cert

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("read MTLS_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return runtimeConfig{}, fmt.Errorf("invalid MTLS_CA_FILE")
	}
	cfg.caPool = pool

	return cfg, nil
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
	if n, err := strconv.Atoi(raw); err == nil {
		return n != 0
	}
	return def
}
