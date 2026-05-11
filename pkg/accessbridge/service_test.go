package accessbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/accesspack"
)

func TestServiceAllowsSignedBridgePathAndRateLimits(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	service, err := NewService(ServiceConfig{
		BridgeConfig: testServiceBridgeConfig(now),
		RPS:          1,
		MaxSources:   16,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	handler := service.Handler()
	healthRR := httptest.NewRecorder()
	handler.ServeHTTP(healthRR, httptest.NewRequest(http.MethodGet, "/health", nil))
	if healthRR.Code != http.StatusOK {
		t.Fatalf("expected health ok, got %d body=%s", healthRR.Code, healthRR.Body.String())
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected bridge ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Referrer-Policy") != "no-referrer" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected bridge security headers, got %+v", rr.Header())
	}
	var out BridgeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal bridge response: %v", err)
	}
	if out.AccessURL != "https://helper.gpm-pilot.net/bridge" || !out.Decision.Allowed {
		t.Fatalf("unexpected bridge response: %+v", out)
	}
	if service.RequestCount("192.0.2.1") != 1 {
		t.Fatalf("expected source request counter to increment")
	}
	limitedRR := httptest.NewRecorder()
	handler.ServeHTTP(limitedRR, httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil))
	if limitedRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit, got %d body=%s", limitedRR.Code, limitedRR.Body.String())
	}
}

func TestServiceRejectsManualPathAndLogsAbuseReport(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	abuseLog := filepath.Join(t.TempDir(), "abuse.jsonl")
	service, err := NewService(ServiceConfig{
		BridgeConfig: testServiceBridgeConfig(now),
		AbuseLogPath: abuseLog,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	handler := service.Handler()
	deniedRR := httptest.NewRecorder()
	handler.ServeHTTP(deniedRR, httptest.NewRequest(http.MethodGet, "/bridge/helper-contact", nil))
	if deniedRR.Code != http.StatusForbidden {
		t.Fatalf("expected manual path denied, got %d body=%s", deniedRR.Code, deniedRR.Body.String())
	}
	abuseRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/abuse", strings.NewReader(`{"path_id":"helper-web","message":"spam burst"}`))
	req.Header.Set("User-Agent", "accessbridge-test")
	handler.ServeHTTP(abuseRR, req)
	if abuseRR.Code != http.StatusAccepted {
		t.Fatalf("expected abuse accepted, got %d body=%s", abuseRR.Code, abuseRR.Body.String())
	}
	if service.AbuseReportCount() != 1 {
		t.Fatalf("expected abuse report counter")
	}
	body, err := os.ReadFile(abuseLog)
	if err != nil {
		t.Fatalf("read abuse log: %v", err)
	}
	if !strings.Contains(string(body), `"message":"spam burst"`) || !strings.Contains(string(body), `"path_id":"helper-web"`) {
		t.Fatalf("unexpected abuse log: %s", string(body))
	}
}

func TestServiceRateLimitsAbuseReports(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	service, err := NewService(ServiceConfig{
		BridgeConfig: testServiceBridgeConfig(now),
		RPS:          1,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	handler := service.Handler()
	req := httptest.NewRequest(http.MethodPost, "/abuse", strings.NewReader(`{"message":"one"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected first abuse report accepted, got %d body=%s", rr.Code, rr.Body.String())
	}
	limitedRR := httptest.NewRecorder()
	handler.ServeHTTP(limitedRR, httptest.NewRequest(http.MethodPost, "/abuse", strings.NewReader(`{"message":"two"}`)))
	if limitedRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected abuse report rate limit, got %d body=%s", limitedRR.Code, limitedRR.Body.String())
	}
}

func TestServiceBridgeLimitDoesNotConsumeAbuseLimit(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	service, err := NewService(ServiceConfig{
		BridgeConfig: testServiceBridgeConfig(now),
		RPS:          1,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	handler := service.Handler()
	bridgeRR := httptest.NewRecorder()
	handler.ServeHTTP(bridgeRR, httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil))
	if bridgeRR.Code != http.StatusOK {
		t.Fatalf("expected bridge request accepted, got %d body=%s", bridgeRR.Code, bridgeRR.Body.String())
	}
	abuseRR := httptest.NewRecorder()
	handler.ServeHTTP(abuseRR, httptest.NewRequest(http.MethodPost, "/abuse", strings.NewReader(`{"message":"bridge did not consume abuse bucket"}`)))
	if abuseRR.Code != http.StatusAccepted {
		t.Fatalf("expected abuse report accepted after bridge request, got %d body=%s", abuseRR.Code, abuseRR.Body.String())
	}
}

func TestServiceTrustsForwardedForOnlyFromLoopback(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	service, err := NewService(ServiceConfig{
		BridgeConfig:      testServiceBridgeConfig(now),
		TrustProxyHeaders: true,
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	loopbackReq := httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil)
	loopbackReq.RemoteAddr = "127.0.0.1:4321"
	loopbackReq.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.2")
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, loopbackReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected loopback proxied request ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	if service.RequestCount("203.0.113.9") != 1 {
		t.Fatalf("expected forwarded client source to be counted")
	}
	remoteReq := httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil)
	remoteReq.RemoteAddr = "198.51.100.7:4321"
	remoteReq.Header.Set("X-Forwarded-For", "203.0.113.10")
	remoteRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(remoteRR, remoteReq)
	if remoteRR.Code != http.StatusOK {
		t.Fatalf("expected remote request ok, got %d body=%s", remoteRR.Code, remoteRR.Body.String())
	}
	if service.RequestCount("198.51.100.7") != 1 {
		t.Fatalf("expected non-loopback forwarded header to be ignored")
	}
}

func TestServiceRequiresAccessCodeWhenConfigured(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	sum := sha256.Sum256([]byte("ticket-123"))
	service, err := NewService(ServiceConfig{
		BridgeConfig:     testServiceBridgeConfig(now),
		AccessCodeSHA256: hex.EncodeToString(sum[:]),
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	handler := service.Handler()
	deniedRR := httptest.NewRecorder()
	handler.ServeHTTP(deniedRR, httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil))
	if deniedRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing code to be unauthorized, got %d body=%s", deniedRR.Code, deniedRR.Body.String())
	}
	allowedRR := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil)
	req.Header.Set("X-GPM-Bridge-Code", "ticket-123")
	handler.ServeHTTP(allowedRR, req)
	if allowedRR.Code != http.StatusOK {
		t.Fatalf("expected correct code to pass, got %d body=%s", allowedRR.Code, allowedRR.Body.String())
	}
	queryRR := httptest.NewRecorder()
	handler.ServeHTTP(queryRR, httptest.NewRequest(http.MethodGet, "/bridge/helper-web?code=ticket-123", nil))
	if queryRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected query code to be disabled by default, got %d body=%s", queryRR.Code, queryRR.Body.String())
	}
}

func TestBadAccessCodesDoNotConsumeBridgeRateLimit(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	sum := sha256.Sum256([]byte("ticket-123"))
	service, err := NewService(ServiceConfig{
		BridgeConfig:     testServiceBridgeConfig(now),
		RPS:              1,
		AccessCodeSHA256: hex.EncodeToString(sum[:]),
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	handler := service.Handler()
	missingRR := httptest.NewRecorder()
	handler.ServeHTTP(missingRR, httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil))
	if missingRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected first bad access-code attempt unauthorized, got %d body=%s", missingRR.Code, missingRR.Body.String())
	}
	wrongReq := httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil)
	wrongReq.Header.Set("X-GPM-Bridge-Code", "wrong-ticket")
	wrongRR := httptest.NewRecorder()
	handler.ServeHTTP(wrongRR, wrongReq)
	if wrongRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected bad access-code attempts to be rate limited, got %d body=%s", wrongRR.Code, wrongRR.Body.String())
	}

	allowedRR := httptest.NewRecorder()
	allowedReq := httptest.NewRequest(http.MethodGet, "/bridge/helper-web", nil)
	allowedReq.Header.Set("X-GPM-Bridge-Code", "ticket-123")
	handler.ServeHTTP(allowedRR, allowedReq)
	if allowedRR.Code != http.StatusOK {
		t.Fatalf("expected valid code to avoid bad-code rate starvation, got %d body=%s", allowedRR.Code, allowedRR.Body.String())
	}
	if service.RequestCount("192.0.2.1") != 1 {
		t.Fatalf("expected only valid bridge request to consume request counter")
	}
}

func TestServiceHealthIncludesPinnedConfigHash(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	service, err := NewService(ServiceConfig{
		BridgeConfig: testServiceBridgeConfig(now),
		ConfigSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected health ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal health response: %v", err)
	}
	if out.ConfigSHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("expected config sha256 in health response, got %+v", out)
	}
}

func TestServiceAllowsQueryAccessCodeOnlyWhenConfigured(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	sum := sha256.Sum256([]byte("ticket-123"))
	service, err := NewService(ServiceConfig{
		BridgeConfig:     testServiceBridgeConfig(now),
		AccessCodeSHA256: hex.EncodeToString(sum[:]),
		AllowQueryCode:   true,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/bridge/helper-web?code=ticket-123", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected query code to pass when enabled, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestNewServiceRejectsExpiredRegistryConfig(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := testServiceBridgeConfig(now)
	config.RegistryExpiresAtUTC = now.Add(-time.Minute).Format(time.RFC3339)
	if _, err := NewService(ServiceConfig{
		BridgeConfig: config,
		Now:          func() time.Time { return now },
	}); err == nil {
		t.Fatal("expected expired registry config to fail preflight")
	}
}

func TestNewServiceRejectsExpiredInviteConfig(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := testServiceBridgeConfig(now)
	expiredNow := now.Add(7*24*time.Hour + time.Minute)
	if _, err := NewService(ServiceConfig{
		BridgeConfig: config,
		Now:          func() time.Time { return expiredNow },
	}); err == nil {
		t.Fatal("expected expired invite config to fail preflight")
	}
}

func TestNewServiceRejectsConfigWithoutServiceablePath(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := testServiceBridgeConfig(now)
	config.AccessPaths = []accesspack.AccessPath{
		{PathID: "manual-a", Kind: "instructions", URL: "mailto:a@helpermail.example", Priority: 10, RequiresExternalApp: true},
		{PathID: "manual-b", Kind: "instructions", URL: "mailto:b@helpermail2.example", Priority: 20, RequiresExternalApp: true},
	}
	if _, err := NewService(ServiceConfig{
		BridgeConfig: config,
		Now:          func() time.Time { return now },
	}); err == nil {
		t.Fatal("expected service with no serviceable HTTP bridge path to fail preflight")
	}
}

func TestNewServiceRejectsUnsafeServiceablePathHosts(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		url  string
	}{
		{name: "plain-http", url: "http://helper.gpm-pilot.net/bridge"},
		{name: "private-ip", url: "https://10.0.0.5/bridge"},
		{name: "loopback-ip", url: "https://127.0.0.1/bridge"},
		{name: "link-local-ip", url: "https://169.254.1.1/bridge"},
		{name: "cgnat-ip", url: "https://100.64.0.10/bridge"},
		{name: "ipv6-loopback", url: "https://[::1]/bridge"},
		{name: "ipv6-link-local", url: "https://[fe80::1]/bridge"},
		{name: "ipv6-ula-fc", url: "https://[fc00::1]/bridge"},
		{name: "ipv6-ula-fd", url: "https://[fd00::1]/bridge"},
		{name: "ipv6-documentation", url: "https://[2001:db8::1]/bridge"},
		{name: "reserved-domain", url: "https://reserved-helper.example/bridge"},
		{name: "tailscale-overlay", url: "https://helper.tailnet.ts.net/bridge"},
		{name: "tailscale-apex-ts-net", url: "https://ts.net/bridge"},
		{name: "tailscale-domain", url: "https://helper.tailscale.net/bridge"},
		{name: "tailscale-apex-domain", url: "https://tailscale.net/bridge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewService(ServiceConfig{
				BridgeConfig: testServiceBridgeConfigWithBridgeURL(now, tc.url),
				Now:          func() time.Time { return now },
			}); err == nil {
				t.Fatal("expected unsafe serviceable bridge path to fail preflight")
			}
		})
	}
}

func testServiceBridgeConfig(now time.Time) accesspack.BridgeServiceConfig {
	return testServiceBridgeConfigWithBridgeURL(now, "https://helper.gpm-pilot.net/bridge")
}

func testServiceBridgeConfigWithBridgeURL(now time.Time, bridgeURL string) accesspack.BridgeServiceConfig {
	invite := accesspack.BridgeInvite{
		SchemaVersion: accesspack.SchemaVersion,
		InviteID:      "bri-service-test",
		Organization: accesspack.Organization{
			OrgID:   "service-org",
			Name:    "Service Org",
			HomeURL: "https://service.example",
		},
		IssuedAtUTC:      now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAtUTC:     now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		IntendedAudience: "users blocked from the service",
		Helper: accesspack.BridgeHelper{
			HelperID:    "helper-service",
			DisplayName: "Service Helper",
			ContactURL:  "https://helper.gpm-pilot.net/contact",
		},
		AccessPaths: []accesspack.AccessPath{
			{PathID: "helper-web", Kind: "bridge", URL: bridgeURL, Priority: 10},
			{PathID: "helper-contact", Kind: "instructions", URL: "mailto:bridge@helpermail.example", Priority: 20, RequiresExternalApp: true},
		},
	}
	registry := accesspack.BridgeHelperRegistry{
		Version: accesspack.BridgeHelperRegistryVersion,
		Helpers: []accesspack.BridgeHelperRegistration{
			{
				HelperID:        "helper-service",
				DisplayName:     "Service Helper",
				Status:          accesspack.BridgeHelperStatusActive,
				OrgIDs:          []string{"service-org"},
				ContactURL:      "https://helper.gpm-pilot.net/contact",
				AbuseReportURL:  "https://helper.gpm-pilot.net/abuse",
				RateLimitPolicy: "beta cap: per-source limits enforced",
				ActiveFromUTC:   now.Add(-2 * time.Hour).Format(time.RFC3339),
				ActiveUntilUTC:  now.Add(8 * 24 * time.Hour).Format(time.RFC3339),
				UpdatedAtUTC:    now.Format(time.RFC3339),
			},
		},
	}
	return accesspack.BuildBridgeServiceConfig(invite, registry, accesspack.BridgeServiceConfigOptions{
		RegistryID:           "service-registry",
		RegistryExpiresAtUTC: now.Add(24 * time.Hour).Format(time.RFC3339),
		InviteKeyID:          "invite-key",
		RegistryKeyID:        "registry-key",
		SignedRegistry:       true,
	}, now)
}
