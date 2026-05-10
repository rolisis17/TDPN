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
	if out.AccessURL != "https://helper.example/bridge" || !out.Decision.Allowed {
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

func testServiceBridgeConfig(now time.Time) accesspack.BridgeServiceConfig {
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
			ContactURL:  "https://helper.example/contact",
		},
		AccessPaths: []accesspack.AccessPath{
			{PathID: "helper-web", Kind: "bridge", URL: "https://helper.example/bridge", Priority: 10},
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
				ContactURL:      "https://helper.example/contact",
				AbuseReportURL:  "https://helper.example/abuse",
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
