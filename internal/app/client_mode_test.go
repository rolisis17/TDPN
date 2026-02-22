package app

import (
	"context"
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
