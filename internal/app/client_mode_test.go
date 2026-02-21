package app

import "testing"

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
