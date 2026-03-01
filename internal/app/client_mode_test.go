package app

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAllowSyntheticFallback(t *testing.T) {
	cases := []struct {
		name   string
		client Client
		want   bool
	}{
		{
			name:   "noop-non-live",
			client: Client{wgBackend: "noop", liveWGMode: false},
			want:   true,
		},
		{
			name:   "live-mode-disabled",
			client: Client{wgBackend: "noop", liveWGMode: true},
			want:   false,
		},
		{
			name:   "command-backend-disabled",
			client: Client{wgBackend: "command", liveWGMode: false},
			want:   false,
		},
		{
			name:   "command-live-disabled",
			client: Client{wgBackend: "command", liveWGMode: true},
			want:   false,
		},
		{
			name:   "explicit-disable",
			client: Client{wgBackend: "noop", liveWGMode: false, disableSynthetic: true},
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
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "DIRECTORY_TRUST_STRICT") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingStartupSyncTimeout(t *testing.T) {
	c := &Client{
		betaStrict:       true,
		trustStrict:      true,
		dataMode:         "opaque",
		innerSource:      "udp",
		wgBackend:        "command",
		wgPrivateKey:     "/tmp/wg.key",
		wgKernelProxy:    true,
		wgProxyAddr:      "127.0.0.1:0",
		liveWGMode:       true,
		disableSynthetic: true,
	}
	err := c.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "CLIENT_STARTUP_SYNC_TIMEOUT_SEC") {
		t.Fatalf("unexpected error: %v", err)
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

func TestNewClientReadsOpaqueSessionEnv(t *testing.T) {
	t.Setenv("CLIENT_OPAQUE_SESSION_SEC", "30")
	t.Setenv("CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS", "2400")
	t.Setenv("CLIENT_STICKY_PAIR_SEC", "75")
	t.Setenv("CLIENT_SESSION_REUSE", "1")
	t.Setenv("CLIENT_SESSION_REFRESH_LEAD_SEC", "55")
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
