package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func TestAllowSyntheticFallback(t *testing.T) {
	cases := []struct {
		name   string
		client *Client
		want   bool
	}{
		{
			name:   "noop-non-live",
			client: &Client{wgBackend: "noop", liveWGMode: false},
			want:   true,
		},
		{
			name:   "live-mode-disabled",
			client: &Client{wgBackend: "noop", liveWGMode: true},
			want:   false,
		},
		{
			name:   "command-backend-disabled",
			client: &Client{wgBackend: "command", liveWGMode: false},
			want:   false,
		},
		{
			name:   "command-live-disabled",
			client: &Client{wgBackend: "command", liveWGMode: true},
			want:   false,
		},
		{
			name:   "explicit-disable",
			client: &Client{wgBackend: "noop", liveWGMode: false, disableSynthetic: true},
			want:   false,
		},
		{
			name:   "wg-only-enforced",
			client: &Client{wgBackend: "noop", liveWGMode: false, wgOnlyMode: true},
			want:   false,
		},
		{
			name:   "beta-strict-enforced",
			client: &Client{wgBackend: "noop", liveWGMode: false, betaStrict: true},
			want:   false,
		},
		{
			name:   "prod-strict-enforced",
			client: &Client{wgBackend: "noop", liveWGMode: false, prodStrict: true},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.client.allowSyntheticFallback(); got != tc.want {
				t.Fatalf("allowSyntheticFallback()=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestSendOpaqueTrafficStrictRealPacketRejectsNonUDPSource(t *testing.T) {
	c := &Client{
		wgOnlyMode:  true,
		innerSource: "synthetic",
	}
	err := c.sendOpaqueTraffic(context.Background(), "127.0.0.1:51980", "session-id")
	if err == nil {
		t.Fatalf("expected strict real-packet mode validation error")
	}
	if !strings.Contains(err.Error(), "strict real-packet mode requires CLIENT_INNER_SOURCE=udp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigLiveModeRequiresSink(t *testing.T) {
	c := &Client{
		dataMode:       "opaque",
		innerSource:    "udp",
		wgBackend:      "command",
		wgPrivateKey:   "/tmp/wg.key",
		liveWGMode:     true,
		opaqueSinkAddr: "",
	}
	if err := c.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected live mode validation error without CLIENT_OPAQUE_SINK_ADDR")
	}
}

func TestValidateRuntimeConfigLiveModeRejectsSyntheticSource(t *testing.T) {
	c := &Client{
		dataMode:       "opaque",
		innerSource:    "synthetic",
		wgBackend:      "command",
		wgPrivateKey:   "/tmp/wg.key",
		wgKernelProxy:  true,
		wgProxyAddr:    "127.0.0.1:0",
		liveWGMode:     true,
		opaqueSinkAddr: "127.0.0.1:53030",
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected live mode validation error for synthetic source")
	}
	if !strings.Contains(err.Error(), "CLIENT_INNER_SOURCE=synthetic") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigCommandModeRequiresOpaqueUDP(t *testing.T) {
	c := &Client{
		dataMode:     "json",
		innerSource:  "synthetic",
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg.key",
	}
	if err := c.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected command mode validation error for non-opaque config")
	}
}

func TestValidateRuntimeConfigDisableSyntheticRequiresUDPSource(t *testing.T) {
	c := &Client{
		dataMode:         "opaque",
		innerSource:      "synthetic",
		wgBackend:        "noop",
		disableSynthetic: true,
	}
	if err := c.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected validation error when synthetic fallback disabled without udp source")
	}
}

func TestValidateRuntimeConfigKernelProxyRequiresCommandBackend(t *testing.T) {
	c := &Client{
		dataMode:         "opaque",
		innerSource:      "synthetic",
		wgBackend:        "noop",
		wgKernelProxy:    true,
		wgProxyAddr:      "127.0.0.1:0",
		wgPrivateKey:     "",
		disableSynthetic: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected kernel proxy validation error")
	}
	if !strings.Contains(err.Error(), "CLIENT_WG_BACKEND=command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigKernelProxyRejectsNonLoopbackProxyAddr(t *testing.T) {
	c := &Client{
		dataMode:      "opaque",
		innerSource:   "udp",
		wgBackend:     "command",
		wgPrivateKey:  "/tmp/wg.key",
		wgKernelProxy: true,
		wgProxyAddr:   "0.0.0.0:52999",
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected non-loopback CLIENT_WG_PROXY_ADDR validation error")
	}
	if !strings.Contains(err.Error(), "CLIENT_WG_PROXY_ADDR must resolve to loopback host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigKernelProxyRejectsEmptyHostProxyAddr(t *testing.T) {
	c := &Client{
		dataMode:      "opaque",
		innerSource:   "udp",
		wgBackend:     "command",
		wgPrivateKey:  "/tmp/wg.key",
		wgKernelProxy: true,
		wgProxyAddr:   ":52999",
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected empty-host CLIENT_WG_PROXY_ADDR validation error")
	}
	if !strings.Contains(err.Error(), "CLIENT_WG_PROXY_ADDR must include an explicit loopback host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigKernelProxyAcceptsLoopbackProxyAddr(t *testing.T) {
	c := &Client{
		dataMode:      "opaque",
		innerSource:   "udp",
		wgBackend:     "command",
		wgPrivateKey:  "/tmp/wg.key",
		wgKernelProxy: true,
		wgProxyAddr:   "127.0.0.1:52999",
	}
	if err := c.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected loopback CLIENT_WG_PROXY_ADDR to validate, got %v", err)
	}
}

func TestValidateRuntimeConfigRejectsSubjectAndAnonCredTogether(t *testing.T) {
	c := &Client{
		dataMode:    "opaque",
		innerSource: "udp",
		wgBackend:   "noop",
		subject:     "client-a",
		anonCred:    "credential-token",
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected subject+anon credential validation error")
	}
	if !strings.Contains(err.Error(), "CLIENT_ANON_CRED") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRequiresCommandKernelLive(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
		requireDistinctOps: true,
	}
	if err := c.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config to validate, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakMode(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      false,
		liveWGMode:         true,
		disableSynthetic:   true,
		opaqueSinkAddr:     "127.0.0.1:53030",
		startupSyncTimeout: time.Second,
		requireDistinctOps: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_WG_KERNEL_PROXY") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingTrustStrict(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        false,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
		requireDistinctOps: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "DIRECTORY_TRUST_STRICT") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsNonUDPInnerSource(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		dataMode:           "opaque",
		innerSource:        "",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
		requireDistinctOps: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_INNER_SOURCE=udp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingStartupSyncTimeout(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		requireDistinctOps: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_STARTUP_SYNC_TIMEOUT_SEC") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingDistinctOperators(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
		requireDistinctOps: false,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_REQUIRE_DISTINCT_OPERATORS") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiDirectoryWithoutSourceQuorum(t *testing.T) {
	c := &Client{
		betaStrict:            true,
		trustStrict:           true,
		dataMode:              "opaque",
		innerSource:           "udp",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg.key",
		wgKernelProxy:         true,
		wgProxyAddr:           "127.0.0.1:0",
		liveWGMode:            true,
		disableSynthetic:      true,
		startupSyncTimeout:    time.Second,
		requireDistinctOps:    true,
		directoryURLs:         []string{"http://127.0.0.1:8081", "http://127.0.0.1:8085"},
		directoryMinSources:   1,
		directoryMinOperators: 2,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "DIRECTORY_MIN_SOURCES>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiDirectoryWithoutOperatorQuorum(t *testing.T) {
	c := &Client{
		betaStrict:            true,
		trustStrict:           true,
		dataMode:              "opaque",
		innerSource:           "udp",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg.key",
		wgKernelProxy:         true,
		wgProxyAddr:           "127.0.0.1:0",
		liveWGMode:            true,
		disableSynthetic:      true,
		startupSyncTimeout:    time.Second,
		requireDistinctOps:    true,
		directoryURLs:         []string{"http://127.0.0.1:8081", "http://127.0.0.1:8085"},
		directoryMinSources:   2,
		directoryMinOperators: 1,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_DIRECTORY_MIN_OPERATORS>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigWGOnlyRequiresDisableSynthetic(t *testing.T) {
	c := &Client{
		wgOnlyMode:         true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   false,
		startupSyncTimeout: time.Second,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected wg-only validation failure")
	}
	if !strings.Contains(err.Error(), "WG_ONLY_MODE requires CLIENT_DISABLE_SYNTHETIC_FALLBACK=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigWGOnlyAcceptsValidConfig(t *testing.T) {
	c := &Client{
		wgOnlyMode:         true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
	}
	if err := c.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected wg-only config valid, got %v", err)
	}
}

func TestEnsureCommandWGPubKeyDerivesWhenUnset(t *testing.T) {
	original := deriveClientWGPublicFromPrivateFile
	defer func() { deriveClientWGPublicFromPrivateFile = original }()

	validPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	called := 0
	deriveClientWGPublicFromPrivateFile = func(_ context.Context, privateKeyPath string) (string, error) {
		called++
		if privateKeyPath != "/tmp/wg-client.key" {
			t.Fatalf("unexpected private key path: %s", privateKeyPath)
		}
		return validPub, nil
	}

	c := &Client{
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-client.key",
		clientWGPub:  "",
	}
	if err := c.ensureCommandWGPubKey(context.Background()); err != nil {
		t.Fatalf("ensure command wg pubkey: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected one derive call, got %d", called)
	}
	if c.clientWGPub != validPub {
		t.Fatalf("expected derived pubkey, got %q", c.clientWGPub)
	}
}

func TestEnsureCommandWGPubKeySkipsDeriveWhenAlreadyValid(t *testing.T) {
	original := deriveClientWGPublicFromPrivateFile
	defer func() { deriveClientWGPublicFromPrivateFile = original }()

	called := 0
	validPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	deriveClientWGPublicFromPrivateFile = func(context.Context, string) (string, error) {
		called++
		return validPub, nil
	}

	c := &Client{
		wgBackend:   "command",
		clientWGPub: validPub,
	}
	if err := c.ensureCommandWGPubKey(context.Background()); err != nil {
		t.Fatalf("ensure command wg pubkey: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected derive call for consistency check, got %d", called)
	}
}

func TestValidatePathOpenWireGuardFields(t *testing.T) {
	validPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name          string
		exitInnerPub  string
		clientInnerIP string
		entryDataAddr string
		wantErr       string
	}{
		{
			name:          "valid",
			exitInnerPub:  validPub,
			clientInnerIP: "10.90.0.2/32",
			entryDataAddr: "127.0.0.1:51820",
			wantErr:       "",
		},
		{
			name:          "invalid exit pubkey",
			exitInnerPub:  "not-a-key",
			clientInnerIP: "10.90.0.2/32",
			entryDataAddr: "127.0.0.1:51820",
			wantErr:       "exit_inner_pub",
		},
		{
			name:          "invalid client inner cidr",
			exitInnerPub:  validPub,
			clientInnerIP: "10.90.0.2",
			entryDataAddr: "127.0.0.1:51820",
			wantErr:       "client_inner_ip",
		},
		{
			name:          "invalid entry data addr",
			exitInnerPub:  validPub,
			clientInnerIP: "10.90.0.2/32",
			entryDataAddr: "bad-host-port",
			wantErr:       "entry_data_addr",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePathOpenWireGuardFields(tc.exitInnerPub, tc.clientInnerIP, tc.entryDataAddr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidatePathOpenEntryDataAddrBinding(t *testing.T) {
	c := &Client{
		exitControlURL: "https://exit.example:8443",
	}
	pair := relayPair{
		entry: proto.RelayDescriptor{
			Endpoint:   "127.0.0.1:51820",
			ControlURL: "https://entry.example:8443",
		},
		exit: proto.RelayDescriptor{
			Endpoint:   "127.0.0.1:51830",
			ControlURL: "https://exit.example:8443",
		},
	}

	if err := c.validatePathOpenEntryDataAddrBinding("https://entry.example:8443", pair, "127.0.0.1:51820"); err != nil {
		t.Fatalf("entry mode binding failed: %v", err)
	}
	if err := c.validatePathOpenEntryDataAddrBinding("https://entry.example:8443", pair, "127.0.0.1:51999"); err == nil {
		t.Fatalf("expected entry mode mismatch rejection")
	}
	if err := c.validatePathOpenEntryDataAddrBinding("https://exit.example:8443", pair, "127.0.0.1:51830"); err != nil {
		t.Fatalf("direct-exit mode binding failed: %v", err)
	}
	if err := c.validatePathOpenEntryDataAddrBinding("https://exit.example:8443", pair, "127.0.0.1:51820"); err == nil {
		t.Fatalf("expected direct-exit mode mismatch rejection")
	}
}

func TestPruneHealthCacheLockedCapsEntries(t *testing.T) {
	c := &Client{
		healthCacheTTL: 5 * time.Second,
		healthCache:    make(map[string]healthProbeState, clientHealthCacheMaxEntries+64),
	}
	now := time.Now()
	for i := 0; i < clientHealthCacheMaxEntries+64; i++ {
		key := fmt.Sprintf("https://relay-%d.example:8443", i)
		c.healthCache[key] = healthProbeState{
			ok:        true,
			checkedAt: now.Add(-time.Duration(i) * time.Millisecond),
		}
	}
	c.pruneHealthCacheLocked(now)
	if len(c.healthCache) > clientHealthCacheMaxEntries {
		t.Fatalf("health cache size=%d exceeds cap=%d", len(c.healthCache), clientHealthCacheMaxEntries)
	}
}

func TestEnsureCommandWGPubKeyRejectsMismatch(t *testing.T) {
	original := deriveClientWGPublicFromPrivateFile
	defer func() { deriveClientWGPublicFromPrivateFile = original }()

	configuredPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	derivedPubBytes := make([]byte, 32)
	derivedPubBytes[0] = 1
	derivedPub := base64.StdEncoding.EncodeToString(derivedPubBytes)

	deriveClientWGPublicFromPrivateFile = func(context.Context, string) (string, error) {
		return derivedPub, nil
	}

	c := &Client{
		wgBackend:   "command",
		clientWGPub: configuredPub,
	}
	if err := c.ensureCommandWGPubKey(context.Background()); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestEnsureCommandWGPubKeyReturnsDeriveError(t *testing.T) {
	original := deriveClientWGPublicFromPrivateFile
	defer func() { deriveClientWGPublicFromPrivateFile = original }()

	deriveClientWGPublicFromPrivateFile = func(context.Context, string) (string, error) {
		return "", errors.New("derive failed")
	}

	c := &Client{
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-client.key",
	}
	if err := c.ensureCommandWGPubKey(context.Background()); err == nil {
		t.Fatalf("expected derive error")
	}
}

func TestNewClientReadsSubjectEnv(t *testing.T) {
	t.Setenv("CLIENT_SUBJECT", "user-123")
	c := NewClient()
	if c.subject != "user-123" {
		t.Fatalf("expected subject from env, got %q", c.subject)
	}
}

func TestNewClientReadsSubjectFromFileEnv(t *testing.T) {
	subjectFile := filepath.Join(t.TempDir(), "client.subject")
	if err := os.WriteFile(subjectFile, []byte("file-user-123\n"), 0o600); err != nil {
		t.Fatalf("write subject file: %v", err)
	}
	t.Setenv("CLIENT_SUBJECT", "")
	t.Setenv("CLIENT_SUBJECT_FILE", subjectFile)
	c := NewClient()
	if c.subject != "file-user-123" {
		t.Fatalf("expected subject from CLIENT_SUBJECT_FILE, got %q", c.subject)
	}
	if _, err := os.Stat(subjectFile); !os.IsNotExist(err) {
		t.Fatalf("expected subject file cleanup, stat err=%v", err)
	}
}

func TestNewClientRejectsSubjectFileSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "subject-target.txt")
	if err := os.WriteFile(target, []byte("file-user-123\n"), 0o600); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	subjectFile := filepath.Join(dir, "client.subject")
	if err := os.Symlink(target, subjectFile); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Setenv("CLIENT_SUBJECT", "")
	t.Setenv("CLIENT_SUBJECT_FILE", subjectFile)
	c := NewClient()
	if c.subject != "" {
		t.Fatalf("expected symlink subject file to be rejected, got %q", c.subject)
	}
	if _, err := os.Stat(subjectFile); err != nil {
		t.Fatalf("expected symlink path to remain after rejected read: %v", err)
	}
}

func TestNewClientRejectsOversizedSubjectFile(t *testing.T) {
	subjectFile := filepath.Join(t.TempDir(), "client.subject")
	oversized := strings.Repeat("a", int(clientSubjectFileMaxBytes)+1)
	if err := os.WriteFile(subjectFile, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write oversized subject file: %v", err)
	}
	t.Setenv("CLIENT_SUBJECT", "")
	t.Setenv("CLIENT_SUBJECT_FILE", subjectFile)
	c := NewClient()
	if c.subject != "" {
		t.Fatalf("expected oversized subject file to be rejected, got %q", c.subject)
	}
	if _, err := os.Stat(subjectFile); err != nil {
		t.Fatalf("expected oversized subject file to remain after rejected read: %v", err)
	}
}

func TestNewClientSubjectEnvPrecedenceOverSubjectFile(t *testing.T) {
	subjectFile := filepath.Join(t.TempDir(), "client.subject")
	if err := os.WriteFile(subjectFile, []byte("file-user-123\n"), 0o600); err != nil {
		t.Fatalf("write subject file: %v", err)
	}
	t.Setenv("CLIENT_SUBJECT", "env-user-123")
	t.Setenv("CLIENT_SUBJECT_FILE", subjectFile)
	c := NewClient()
	if c.subject != "env-user-123" {
		t.Fatalf("expected CLIENT_SUBJECT precedence, got %q", c.subject)
	}
}

func TestNewClientDirectoryTrustTOFUDefaultsDisabled(t *testing.T) {
	t.Setenv("DIRECTORY_TRUST_TOFU", "")
	c := NewClient()
	if c.trustTOFU {
		t.Fatalf("expected DIRECTORY_TRUST_TOFU default disabled")
	}
}

func TestNewClientDirectoryTrustTOFUOptInEnabled(t *testing.T) {
	t.Setenv("DIRECTORY_TRUST_TOFU", "1")
	c := NewClient()
	if !c.trustTOFU {
		t.Fatalf("expected DIRECTORY_TRUST_TOFU=1 to enable TOFU")
	}
}

func TestNewClientReadsOpaqueSessionEnv(t *testing.T) {
	t.Setenv("CLIENT_OPAQUE_SESSION_SEC", "30")
	t.Setenv("CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS", "2400")
	t.Setenv("CLIENT_STICKY_PAIR_SEC", "75")
	t.Setenv("CLIENT_SESSION_REUSE", "1")
	t.Setenv("CLIENT_SESSION_REFRESH_LEAD_SEC", "55")
	t.Setenv("CLIENT_SESSION_MIN_REFRESH_SEC", "12")
	c := NewClient()
	if c.opaqueSessionSec != 30 {
		t.Fatalf("expected CLIENT_OPAQUE_SESSION_SEC parsed, got %d", c.opaqueSessionSec)
	}
	if c.opaqueInitialUpMS != 2400 {
		t.Fatalf("expected CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS parsed, got %d", c.opaqueInitialUpMS)
	}
	if c.stickyPairSec != 75 {
		t.Fatalf("expected CLIENT_STICKY_PAIR_SEC parsed, got %d", c.stickyPairSec)
	}
	if !c.sessionReuse {
		t.Fatalf("expected CLIENT_SESSION_REUSE parsed true")
	}
	if c.sessionRefreshLeadSec != 55 {
		t.Fatalf("expected CLIENT_SESSION_REFRESH_LEAD_SEC parsed, got %d", c.sessionRefreshLeadSec)
	}
	if c.sessionMinRefreshSec != 12 {
		t.Fatalf("expected CLIENT_SESSION_MIN_REFRESH_SEC parsed, got %d", c.sessionMinRefreshSec)
	}
}

func TestNewClientSessionReuseDefaultsEnabledWhenUnset(t *testing.T) {
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "0")
	t.Setenv("CLIENT_SESSION_REUSE", "")
	c := NewClient()
	if !c.sessionReuse {
		t.Fatalf("expected session reuse enabled by default when CLIENT_SESSION_REUSE is unset")
	}
}

func TestNewClientSessionReuseExplicitDisableWithoutDirectExitOverride(t *testing.T) {
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "0")
	t.Setenv("CLIENT_SESSION_REUSE", "0")
	c := NewClient()
	if c.sessionReuse {
		t.Fatalf("expected CLIENT_SESSION_REUSE=0 to disable session reuse when direct-exit override is not active")
	}
}

func TestNewClientForceDirectExitDefaultsSessionReuse(t *testing.T) {
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "1")
	t.Setenv("CLIENT_SESSION_REUSE", "")
	c := NewClient()
	if !c.sessionReuse {
		t.Fatalf("expected CLIENT_FORCE_DIRECT_EXIT to default CLIENT_SESSION_REUSE to true when unset")
	}
	if c.stickyPairSec != 300 {
		t.Fatalf("expected CLIENT_FORCE_DIRECT_EXIT to default CLIENT_STICKY_PAIR_SEC=300, got %d", c.stickyPairSec)
	}
	if c.sessionMinRefreshSec != 6 {
		t.Fatalf("expected CLIENT_FORCE_DIRECT_EXIT to default CLIENT_SESSION_MIN_REFRESH_SEC=6, got %d", c.sessionMinRefreshSec)
	}
}

func TestNewClientForceDirectExitOverridesExplicitSessionReuseDisable(t *testing.T) {
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "1")
	t.Setenv("CLIENT_SESSION_REUSE", "0")
	c := NewClient()
	if !c.sessionReuse {
		t.Fatalf("expected direct-exit mode to force session reuse on by default")
	}
}

func TestNewClientDirectExitAllowSessionChurnRespectsExplicitDisable(t *testing.T) {
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "1")
	t.Setenv("CLIENT_SESSION_REUSE", "0")
	t.Setenv("CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN", "1")
	c := NewClient()
	if c.sessionReuse {
		t.Fatalf("expected CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN=1 to preserve explicit CLIENT_SESSION_REUSE=0")
	}
	if c.sessionMinRefreshSec != 0 {
		t.Fatalf("expected churn mode to avoid forced CLIENT_SESSION_MIN_REFRESH_SEC default, got %d", c.sessionMinRefreshSec)
	}
}

func TestNewClientForceDirectExitSessionMinRefreshExplicitOverride(t *testing.T) {
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "1")
	t.Setenv("CLIENT_SESSION_MIN_REFRESH_SEC", "0")
	c := NewClient()
	if c.sessionMinRefreshSec != 0 {
		t.Fatalf("expected explicit CLIENT_SESSION_MIN_REFRESH_SEC=0 to override direct-exit default, got %d", c.sessionMinRefreshSec)
	}
}

func TestNewClientPathProfileDefaultsTo2Hop(t *testing.T) {
	t.Setenv("CLIENT_PATH_PROFILE", "")
	c := NewClient()
	if c.pathProfile != "2hop" {
		t.Fatalf("expected default path profile 2hop, got %q", c.pathProfile)
	}
	if c.preferMiddleRelay {
		t.Fatalf("expected middle preference disabled for default 2hop profile")
	}
}

func TestNewClientPathProfile3HopEnablesMiddlePreference(t *testing.T) {
	t.Setenv("CLIENT_PATH_PROFILE", "3hop")
	c := NewClient()
	if c.pathProfile != "3hop" {
		t.Fatalf("expected path profile 3hop, got %q", c.pathProfile)
	}
	if !c.preferMiddleRelay {
		t.Fatalf("expected middle preference enabled for 3hop profile")
	}
	if !c.requireMiddleRelay {
		t.Fatalf("expected 3hop profile to require middle relay by default")
	}
}

func TestNewClientRequireMiddleRelayEnvOverrideOn(t *testing.T) {
	t.Setenv("CLIENT_PATH_PROFILE", "2hop")
	t.Setenv("CLIENT_REQUIRE_MIDDLE_RELAY", "1")
	c := NewClient()
	if !c.requireMiddleRelay {
		t.Fatalf("expected CLIENT_REQUIRE_MIDDLE_RELAY=1 to enable strict middle relay requirement")
	}
}

func TestNewClientRequireMiddleRelayEnvOverrideOffFor3Hop(t *testing.T) {
	t.Setenv("CLIENT_PATH_PROFILE", "3hop")
	t.Setenv("CLIENT_REQUIRE_MIDDLE_RELAY", "0")
	c := NewClient()
	if c.requireMiddleRelay {
		t.Fatalf("expected CLIENT_REQUIRE_MIDDLE_RELAY=0 to disable strict middle relay requirement override")
	}
}

func TestNewClientReadsWGKernelProxyEnv(t *testing.T) {
	t.Setenv("CLIENT_WG_KERNEL_PROXY", "1")
	t.Setenv("CLIENT_WG_PROXY_ADDR", "127.0.0.1:52999")
	c := NewClient()
	if !c.wgKernelProxy {
		t.Fatalf("expected CLIENT_WG_KERNEL_PROXY parsed true")
	}
	if c.wgProxyAddr != "127.0.0.1:52999" {
		t.Fatalf("expected CLIENT_WG_PROXY_ADDR parsed, got %s", c.wgProxyAddr)
	}
}

func TestNewClientReadsBootstrapBackoffEnv(t *testing.T) {
	t.Setenv("CLIENT_BOOTSTRAP_INTERVAL_SEC", "3")
	t.Setenv("CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC", "11")
	t.Setenv("CLIENT_BOOTSTRAP_JITTER_PCT", "37")
	t.Setenv("CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC", "4")
	c := NewClient()
	if c.bootstrapInterval != 3*time.Second {
		t.Fatalf("expected CLIENT_BOOTSTRAP_INTERVAL_SEC parsed, got %s", c.bootstrapInterval)
	}
	if c.bootstrapBackoffMax != 11*time.Second {
		t.Fatalf("expected CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC parsed, got %s", c.bootstrapBackoffMax)
	}
	if c.bootstrapJitterPct != 37 {
		t.Fatalf("expected CLIENT_BOOTSTRAP_JITTER_PCT parsed, got %d", c.bootstrapJitterPct)
	}
	if c.bootstrapInitialDelay != 4*time.Second {
		t.Fatalf("expected CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC parsed, got %s", c.bootstrapInitialDelay)
	}
}

func TestNewClientDefaultInnerSourceSyntheticInNoopMode(t *testing.T) {
	t.Setenv("CLIENT_INNER_SOURCE", "")
	t.Setenv("CLIENT_WG_BACKEND", "noop")
	t.Setenv("CLIENT_WG_KERNEL_PROXY", "0")
	t.Setenv("CLIENT_LIVE_WG_MODE", "0")
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	t.Setenv("WG_ONLY_MODE", "0")
	c := NewClient()
	if c.innerSource != "synthetic" {
		t.Fatalf("expected noop-mode default inner source synthetic, got %q", c.innerSource)
	}
}

func TestNewClientCommandBackendDefaultsInnerSourceUDP(t *testing.T) {
	t.Setenv("CLIENT_INNER_SOURCE", "")
	t.Setenv("CLIENT_WG_BACKEND", "command")
	t.Setenv("CLIENT_WG_KERNEL_PROXY", "0")
	t.Setenv("CLIENT_LIVE_WG_MODE", "0")
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	t.Setenv("WG_ONLY_MODE", "0")
	c := NewClient()
	if c.innerSource != "udp" {
		t.Fatalf("expected command-mode default inner source udp, got %q", c.innerSource)
	}
}

func TestNewClientKernelProxyDefaultsInnerSourceUDP(t *testing.T) {
	t.Setenv("CLIENT_INNER_SOURCE", "")
	t.Setenv("CLIENT_WG_BACKEND", "noop")
	t.Setenv("CLIENT_WG_KERNEL_PROXY", "1")
	t.Setenv("CLIENT_LIVE_WG_MODE", "0")
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	t.Setenv("WG_ONLY_MODE", "0")
	c := NewClient()
	if c.innerSource != "udp" {
		t.Fatalf("expected kernel-proxy default inner source udp, got %q", c.innerSource)
	}
}

func TestNewClientCommandBackendDefaultStartupSyncTimeout(t *testing.T) {
	t.Setenv("CLIENT_WG_BACKEND", "command")
	t.Setenv("CLIENT_STARTUP_SYNC_TIMEOUT_SEC", "")
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	c := NewClient()
	if c.startupSyncTimeout != 8*time.Second {
		t.Fatalf("expected command default startup sync timeout 8s, got %s", c.startupSyncTimeout)
	}
}

func TestNewClientStartupSyncTimeoutOverride(t *testing.T) {
	t.Setenv("CLIENT_WG_BACKEND", "command")
	t.Setenv("CLIENT_STARTUP_SYNC_TIMEOUT_SEC", "5")
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	c := NewClient()
	if c.startupSyncTimeout != 5*time.Second {
		t.Fatalf("expected startup sync timeout override 5s, got %s", c.startupSyncTimeout)
	}
}

func TestNewClientStrictStartupSyncTimeoutDefault(t *testing.T) {
	t.Setenv("CLIENT_WG_BACKEND", "command")
	t.Setenv("CLIENT_STARTUP_SYNC_TIMEOUT_SEC", "")
	t.Setenv("BETA_STRICT_MODE", "1")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	c := NewClient()
	if c.startupSyncTimeout != 10*time.Second {
		t.Fatalf("expected strict startup sync timeout 10s, got %s", c.startupSyncTimeout)
	}
}

func TestNewClientWGOnlyStartupSyncTimeoutDefault(t *testing.T) {
	t.Setenv("WG_ONLY_MODE", "1")
	t.Setenv("CLIENT_STARTUP_SYNC_TIMEOUT_SEC", "")
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("CLIENT_BETA_STRICT", "0")
	c := NewClient()
	if c.startupSyncTimeout != 10*time.Second {
		t.Fatalf("expected wg-only startup sync timeout 10s, got %s", c.startupSyncTimeout)
	}
}

func TestNewClientProdStrictEnablesWGOnly(t *testing.T) {
	t.Setenv("PROD_STRICT_MODE", "1")
	c := NewClient()
	if !c.wgOnlyMode {
		t.Fatalf("expected prod strict mode to enable wg-only mode")
	}
}

func TestValidateRuntimeConfigForceDirectExitRejectsStrictModes(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
		requireDistinctOps: true,
		forceDirectExit:    true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict-mode rejection for CLIENT_FORCE_DIRECT_EXIT")
	}
	if !strings.Contains(err.Error(), "CLIENT_FORCE_DIRECT_EXIT is not allowed in strict modes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRequiresTrustTOFUDisabled(t *testing.T) {
	c := &Client{
		betaStrict:         true,
		trustStrict:        true,
		trustTOFU:          true,
		dataMode:           "opaque",
		innerSource:        "udp",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg.key",
		wgKernelProxy:      true,
		wgProxyAddr:        "127.0.0.1:0",
		liveWGMode:         true,
		disableSynthetic:   true,
		startupSyncTimeout: time.Second,
		requireDistinctOps: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected beta strict to reject DIRECTORY_TRUST_TOFU")
	}
	if !strings.Contains(err.Error(), "DIRECTORY_TRUST_TOFU=0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsDirectExitWith3HopProfile(t *testing.T) {
	c := &Client{
		pathProfile:              "3hop",
		dataMode:                 "json",
		innerSource:              "synthetic",
		wgBackend:                "noop",
		requireDistinctOps:       false,
		allowDirectExitFallback:  true,
		forceDirectExit:          true,
		requireDistinctCountries: false,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected direct-exit and 3hop profile conflict validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_PATH_PROFILE=3hop is incompatible with CLIENT_FORCE_DIRECT_EXIT=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigForceDirectExitRequiresFallbackEnabled(t *testing.T) {
	c := &Client{
		dataMode:                "json",
		innerSource:             "synthetic",
		wgBackend:               "noop",
		requireDistinctOps:      false,
		allowDirectExitFallback: false,
		forceDirectExit:         true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected fallback-enable validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_FORCE_DIRECT_EXIT requires CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigForceDirectExitRequiresDistinctOperatorsDisabled(t *testing.T) {
	c := &Client{
		dataMode:                "json",
		innerSource:             "synthetic",
		wgBackend:               "noop",
		requireDistinctOps:      true,
		allowDirectExitFallback: true,
		forceDirectExit:         true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected distinct-operator validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_FORCE_DIRECT_EXIT requires CLIENT_REQUIRE_DISTINCT_OPERATORS=0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigForceDirectExitAcceptsNonStrictConfig(t *testing.T) {
	c := &Client{
		dataMode:                "json",
		innerSource:             "synthetic",
		wgBackend:               "noop",
		requireDistinctOps:      false,
		allowDirectExitFallback: true,
		forceDirectExit:         true,
	}
	if err := c.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected non-strict force-direct config to validate, got %v", err)
	}
}

func TestBootstrapDelayForFailures(t *testing.T) {
	base := 2 * time.Second
	maxDelay := 9 * time.Second
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: 2 * time.Second},
		{failures: 1, want: 2 * time.Second},
		{failures: 2, want: 4 * time.Second},
		{failures: 3, want: 8 * time.Second},
		{failures: 4, want: 9 * time.Second},
		{failures: 9, want: 9 * time.Second},
	}
	for _, tc := range cases {
		if got := bootstrapDelayForFailures(base, maxDelay, tc.failures); got != tc.want {
			t.Fatalf("failures=%d got=%s want=%s", tc.failures, got, tc.want)
		}
	}
}

func TestBootstrapDelayWithJitter(t *testing.T) {
	delay := 10 * time.Second
	maxDelay := 20 * time.Second
	if got := bootstrapDelayWithJitter(delay, maxDelay, 0, 0.9); got != delay {
		t.Fatalf("expected unchanged delay without jitter, got %s", got)
	}
	if got := bootstrapDelayWithJitter(delay, maxDelay, 20, 0.0); got != 8*time.Second {
		t.Fatalf("expected low-bound jitter, got %s", got)
	}
	if got := bootstrapDelayWithJitter(delay, maxDelay, 20, 0.5); got != 10*time.Second {
		t.Fatalf("expected center jitter, got %s", got)
	}
	if got := bootstrapDelayWithJitter(delay, maxDelay, 20, 1.0); got != 12*time.Second {
		t.Fatalf("expected high-bound jitter, got %s", got)
	}
}

func TestBootstrapDelayWithJitterClampsMax(t *testing.T) {
	delay := 10 * time.Second
	maxDelay := 10 * time.Second
	if got := bootstrapDelayWithJitter(delay, maxDelay, 40, 1.0); got != 10*time.Second {
		t.Fatalf("expected jittered delay clamped to max, got %s", got)
	}
}

func TestActiveSessionNeedsRefresh(t *testing.T) {
	now := time.Now()
	c := &Client{sessionRefreshLeadSec: 20}
	if !c.activeSessionNeedsRefresh(clientActiveSession{sessionExp: now.Add(10 * time.Second).Unix()}, now) {
		t.Fatalf("expected refresh required for near-expiry session")
	}
	if c.activeSessionNeedsRefresh(clientActiveSession{sessionExp: now.Add(45 * time.Second).Unix()}, now) {
		t.Fatalf("expected no refresh required for far-expiry session")
	}
	if !c.activeSessionNeedsRefresh(clientActiveSession{sessionExp: 0}, now) {
		t.Fatalf("expected refresh required when session expiry missing")
	}
}

func TestActiveSessionNeedsRefreshDirectExitUsesAdaptiveLead(t *testing.T) {
	now := time.Now()
	c := &Client{
		forceDirectExit:       true,
		sessionRefreshLeadSec: 20,
	}
	session := clientActiveSession{sessionExp: now.Add(5 * time.Second).Unix()}
	if c.activeSessionNeedsRefresh(session, now) {
		t.Fatalf("expected short-lived direct-exit session to avoid immediate refresh churn")
	}
	if !c.activeSessionNeedsRefresh(session, now.Add(4*time.Second)) {
		t.Fatalf("expected short-lived direct-exit session to refresh near expiry")
	}
}

func TestActiveSessionNeedsRefreshMinIntervalSuppressesEarlyRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := &Client{
		sessionRefreshLeadSec: 20,
		sessionMinRefreshSec:  6,
	}
	session := clientActiveSession{
		sessionExp:    now.Add(10 * time.Second).Unix(),
		establishedAt: now.Add(-3 * time.Second),
	}
	if c.activeSessionNeedsRefresh(session, now) {
		t.Fatalf("expected min refresh interval to suppress early refresh")
	}
}

func TestActiveSessionNeedsRefreshNearExpiryBypassesMinInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := &Client{
		sessionRefreshLeadSec: 20,
		sessionMinRefreshSec:  60,
	}
	session := clientActiveSession{
		sessionExp:    now.Add(1 * time.Second).Unix(),
		establishedAt: now,
	}
	if !c.activeSessionNeedsRefresh(session, now) {
		t.Fatalf("expected near-expiry session to refresh even before min refresh interval")
	}
}

func TestTryReuseActiveSessionRefreshKeepsSessionForHandoff(t *testing.T) {
	now := time.Now()
	c := &Client{
		sessionReuse:          true,
		sessionRefreshLeadSec: 20,
	}
	c.storeActiveSession(clientActiveSession{
		sessionID:     "session-old",
		sessionExp:    now.Add(10 * time.Second).Unix(),
		entryRelayID:  "entry-a",
		exitRelayID:   "exit-a",
		entryDataAddr: "127.0.0.1:51820",
	})
	if reused := c.tryReuseActiveSession(context.Background(), now); reused {
		t.Fatalf("expected refresh-needed path to avoid immediate reuse")
	}
	session, ok := c.snapshotActiveSession()
	if !ok {
		t.Fatalf("expected active session retained for handoff")
	}
	if session.sessionID != "session-old" {
		t.Fatalf("unexpected retained session id=%s", session.sessionID)
	}
}

func TestTryReuseActiveSessionExpiredClearsSession(t *testing.T) {
	now := time.Now()
	c := &Client{
		sessionReuse:          true,
		sessionRefreshLeadSec: 20,
	}
	c.storeActiveSession(clientActiveSession{
		sessionID:  "session-expired",
		sessionExp: now.Add(-2 * time.Second).Unix(),
	})
	if reused := c.tryReuseActiveSession(context.Background(), now); reused {
		t.Fatalf("expected expired session to skip reuse")
	}
	if _, ok := c.snapshotActiveSession(); ok {
		t.Fatalf("expected expired active session to be cleared")
	}
}

func TestCloseSessionPathCloseFailureIsBestEffort(t *testing.T) {
	c := &Client{
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}
	session := clientActiveSession{
		sessionID:       "session-1",
		entryControlURL: "http://127.0.0.1:1",
		transport:       "policy-json",
	}
	if err := c.closeSession(context.Background(), session); err != nil {
		t.Fatalf("expected closeSession to ignore close-path failures, got %v", err)
	}
}

func TestNormalizeControlURLRejectsNonLoopbackHTTPInStrictMode(t *testing.T) {
	t.Setenv("CLIENT_BETA_STRICT", "1")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	if got := normalizeControlURL("http://directory.example.invalid:8081"); got != "" {
		t.Fatalf("expected non-loopback http URL to be rejected in strict mode, got %q", got)
	}
}

func TestNormalizeControlURLRejectsNonLoopbackHTTPWithGlobalStrictMode(t *testing.T) {
	t.Setenv("CLIENT_BETA_STRICT", "")
	t.Setenv("CLIENT_PROD_STRICT", "")
	t.Setenv("BETA_STRICT_MODE", "1")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	if got := normalizeControlURL("http://directory.example.invalid:8081"); got != "" {
		t.Fatalf("expected global strict mode to reject non-loopback http URL, got %q", got)
	}
}

func TestNormalizeControlURLAllowsNonLoopbackHTTPWithDangerousOverrideInStrictMode(t *testing.T) {
	t.Setenv("CLIENT_BETA_STRICT", "1")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "1")
	got := normalizeControlURL("http://directory.example.invalid:8081")
	if got != "http://directory.example.invalid:8081" {
		t.Fatalf("expected dangerous override to allow url, got %q", got)
	}
}

func TestNormalizeControlURLAllowsLoopbackHTTPByDefault(t *testing.T) {
	t.Setenv("CLIENT_BETA_STRICT", "1")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	got := normalizeControlURL("http://127.0.0.1:8081")
	if got != "http://127.0.0.1:8081" {
		t.Fatalf("expected loopback http URL to remain allowed, got %q", got)
	}
}

func TestNormalizeControlURLRejectsNonLoopbackHTTPByDefaultOutsideStrictMode(t *testing.T) {
	t.Setenv("CLIENT_BETA_STRICT", "")
	t.Setenv("CLIENT_PROD_STRICT", "")
	t.Setenv("CLIENT_REQUIRE_HTTPS_CONTROL_URL", "")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	got := normalizeControlURL("http://directory.example.invalid:8081")
	if got != "" {
		t.Fatalf("expected non-loopback http URL to be rejected by default, got %q", got)
	}
}

func TestNormalizeControlURLAllowsNonLoopbackHTTPWhenRequireHTTPSDisabled(t *testing.T) {
	t.Setenv("CLIENT_BETA_STRICT", "")
	t.Setenv("CLIENT_PROD_STRICT", "")
	t.Setenv("CLIENT_REQUIRE_HTTPS_CONTROL_URL", "0")
	t.Setenv("CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	got := normalizeControlURL("http://directory.example.invalid:8081")
	if got != "http://directory.example.invalid:8081" {
		t.Fatalf("expected CLIENT_REQUIRE_HTTPS_CONTROL_URL=0 to allow URL, got %q", got)
	}
}
