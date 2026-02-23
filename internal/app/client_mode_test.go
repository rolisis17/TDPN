package app

import (
	"context"
	"encoding/base64"
	"errors"
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
