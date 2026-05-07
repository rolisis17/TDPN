package settlement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type stubCosmosOutboundResolver struct {
	ips map[string][]net.IPAddr
	err error
}

func (s stubCosmosOutboundResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.ips[strings.ToLower(host)], nil
}

func writeSignedTxSuccessResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"tx_response":{"code":0}}`)
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestCosmosAdapterHealthPaths(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    srv.URL,
			QueueSize:   8,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		if err := adapter.Health(context.Background()); err != nil {
			t.Fatalf("Health expected nil error, got %v", err)
		}
	})

	t.Run("failure_non_200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    srv.URL,
			QueueSize:   8,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		err = adapter.Health(context.Background())
		if err == nil {
			t.Fatalf("Health expected non-200 error")
		}
		if !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("expected status 503 health error, got %v", err)
		}
	})

	t.Run("failure_client_unavailable", func(t *testing.T) {
		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    "http://127.0.0.1:1",
			QueueSize:   8,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		adapter.client = &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("transport unavailable")
			}),
		}

		err = adapter.Health(context.Background())
		if err == nil {
			t.Fatalf("Health expected client transport error")
		}
		if !strings.Contains(err.Error(), "transport unavailable") {
			t.Fatalf("unexpected health transport error: %v", err)
		}
	})
}

func TestCosmosAdapterVerifyRewardProofQueriesRegistryAndBindsRewardMaterial(t *testing.T) {
	issuedAt := time.Date(2026, 4, 20, 1, 2, 3, 456789000, time.UTC)
	periodStart := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := "obj://traffic-proof/reward-verify-1"
	seenPath := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/x/vpnrewards/proofs/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		select {
		case seenPath <- r.URL.Path:
		default:
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proof": map[string]any{
				"verified":            true,
				"verifier_id":         "proof-registry-test",
				"verified_at_utc":     issuedAt.Add(time.Minute).Format(time.RFC3339),
				"traffic_proof_ref":   proofRef,
				"trust_contract":      string(RewardProofTrustContractObjectiveTrafficV1),
				"reward_id":           "reward-proof-verify-1",
				"provider_subject_id": "provider-proof-verify-1",
				"session_id":          "session-proof-verify-1",
				"payout_period_start": periodStart.Format(time.RFC3339),
				"payout_period_end":   periodEnd.Format(time.RFC3339),
				"reward_micros":       int64(1234),
				"currency":            "TDPNC",
				"issued_at":           issuedAt.Truncate(time.Second).Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           time.Millisecond,
		RewardProofVerifierID: "proof-registry-test",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	verification, err := adapter.VerifyRewardProof(context.Background(), RewardProofVerificationRequest{
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		TrafficProofRef:   proofRef,
		RewardID:          "reward-proof-verify-1",
		ProviderSubjectID: "provider-proof-verify-1",
		SessionID:         "session-proof-verify-1",
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodEnd,
		RewardMicros:      1234,
		Currency:          "TDPNC",
		IssuedAt:          issuedAt,
	})
	if err != nil {
		t.Fatalf("VerifyRewardProof: %v", err)
	}
	if !verification.Verified || verification.VerifierID != "proof-registry-test" {
		t.Fatalf("verification=%+v want verified proof-registry-test", verification)
	}
	select {
	case path := <-seenPath:
		if !strings.Contains(path, "/x/vpnrewards/proofs/") {
			t.Fatalf("unexpected proof path %q", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for proof registry query")
	}
}

func TestCosmosAdapterVerifyRewardProofRejectsUnexpectedVerifierID(t *testing.T) {
	issuedAt := time.Date(2026, 4, 20, 1, 2, 3, 0, time.UTC)
	periodStart := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := "obj://traffic-proof/reward-verify-verifier-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proof": map[string]any{
				"verified":            true,
				"verifier_id":         "untrusted-verifier",
				"verified_at_utc":     issuedAt.Add(time.Minute).Format(time.RFC3339),
				"traffic_proof_ref":   proofRef,
				"trust_contract":      string(RewardProofTrustContractObjectiveTrafficV1),
				"reward_id":           "reward-proof-verifier-1",
				"provider_subject_id": "provider-proof-verifier-1",
				"session_id":          "session-proof-verifier-1",
				"payout_period_start": periodStart.Format(time.RFC3339),
				"payout_period_end":   periodEnd.Format(time.RFC3339),
				"reward_micros":       int64(1234),
				"currency":            "TDPNC",
				"issued_at":           issuedAt.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           time.Millisecond,
		RewardProofVerifierID: "trusted-verifier",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.VerifyRewardProof(context.Background(), RewardProofVerificationRequest{
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		TrafficProofRef:   proofRef,
		RewardID:          "reward-proof-verifier-1",
		ProviderSubjectID: "provider-proof-verifier-1",
		SessionID:         "session-proof-verifier-1",
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodEnd,
		RewardMicros:      1234,
		Currency:          "TDPNC",
		IssuedAt:          issuedAt,
	})
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected unauthorized verifier rejection, got %v", err)
	}
}

func TestCosmosAdapterVerifyRewardProofRequiresExpectedVerifierID(t *testing.T) {
	issuedAt := time.Date(2026, 4, 20, 1, 2, 3, 0, time.UTC)
	periodStart := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := "obj://traffic-proof/reward-verify-verifier-required-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proof": map[string]any{
				"verified":            true,
				"verifier_id":         "proof-registry-test",
				"verified_at_utc":     issuedAt.Add(time.Minute).Format(time.RFC3339),
				"traffic_proof_ref":   proofRef,
				"trust_contract":      string(RewardProofTrustContractObjectiveTrafficV1),
				"reward_id":           "reward-proof-verifier-required-1",
				"provider_subject_id": "provider-proof-verifier-required-1",
				"session_id":          "session-proof-verifier-required-1",
				"payout_period_start": periodStart.Format(time.RFC3339),
				"payout_period_end":   periodEnd.Format(time.RFC3339),
				"reward_micros":       int64(1234),
				"currency":            "TDPNC",
				"issued_at":           issuedAt.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.VerifyRewardProof(context.Background(), RewardProofVerificationRequest{
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		TrafficProofRef:   proofRef,
		RewardID:          "reward-proof-verifier-required-1",
		ProviderSubjectID: "provider-proof-verifier-required-1",
		SessionID:         "session-proof-verifier-required-1",
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodEnd,
		RewardMicros:      1234,
		Currency:          "TDPNC",
		IssuedAt:          issuedAt,
	})
	if err == nil || !strings.Contains(err.Error(), "verifier id is required") {
		t.Fatalf("expected missing expected verifier rejection, got %v", err)
	}
}

func TestCosmosAdapterVerifyRewardProofRejectsUnexpectedPayoutPeriod(t *testing.T) {
	issuedAt := time.Date(2026, 4, 20, 1, 2, 3, 0, time.UTC)
	periodStart := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := "obj://traffic-proof/reward-verify-period-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proof": map[string]any{
				"verified":            true,
				"verifier_id":         "proof-registry-test",
				"verified_at_utc":     issuedAt.Add(time.Minute).Format(time.RFC3339),
				"traffic_proof_ref":   proofRef,
				"trust_contract":      string(RewardProofTrustContractObjectiveTrafficV1),
				"reward_id":           "reward-proof-verify-period-1",
				"provider_subject_id": "provider-proof-verify-period-1",
				"session_id":          "session-proof-verify-period-1",
				"payout_period_start": periodStart.Format(time.RFC3339),
				"payout_period_end":   periodEnd.Format(time.RFC3339),
				"reward_micros":       int64(1234),
				"currency":            "TDPNC",
				"issued_at":           issuedAt.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           time.Millisecond,
		RewardProofVerifierID: "proof-registry-test",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.VerifyRewardProof(context.Background(), RewardProofVerificationRequest{
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		TrafficProofRef:   proofRef,
		RewardID:          "reward-proof-verify-period-1",
		ProviderSubjectID: "provider-proof-verify-period-1",
		SessionID:         "session-proof-verify-period-1",
		RewardMicros:      1234,
		Currency:          "TDPNC",
		IssuedAt:          issuedAt,
	})
	if err == nil || !strings.Contains(err.Error(), "payout_period_start mismatch") {
		t.Fatalf("expected payout period mismatch, got %v", err)
	}
}

func TestNewCosmosAdapterRejectsNonLoopbackHTTPWithoutOverride(t *testing.T) {
	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://example.com",
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err == nil {
		t.Fatalf("expected non-loopback http endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "must use https for non-loopback hosts") {
		t.Fatalf("expected https enforcement error, got %v", err)
	}
}

func TestNewCosmosAdapterAllowsNonLoopbackHTTPWithOverride(t *testing.T) {
	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:          "http://example.com",
		AllowInsecureHTTP: true,
		QueueSize:         8,
		MaxRetries:        1,
		BaseBackoff:       5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected allow-insecure-http override to permit endpoint, got %v", err)
	}
	adapter.Close()
}

func TestNewCosmosAdapterRejectsLocalhostHTTPWithMixedResolution(t *testing.T) {
	originalLookup := cosmosLookupIPAddrs
	t.Cleanup(func() {
		cosmosLookupIPAddrs = originalLookup
	})
	cosmosLookupIPAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("198.51.100.7")},
		}, nil
	}

	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://localhost:1317",
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err == nil {
		t.Fatalf("expected mixed-resolution localhost endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "must use https for non-loopback hosts") {
		t.Fatalf("expected https enforcement error, got %v", err)
	}
}

func TestNewCosmosAdapterAllowsLocalhostHTTPWhenAllResolvedIPsAreLoopback(t *testing.T) {
	originalLookup := cosmosLookupIPAddrs
	t.Cleanup(func() {
		cosmosLookupIPAddrs = originalLookup
	})
	cosmosLookupIPAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("::1")},
		}, nil
	}

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://localhost:1317",
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("expected all-loopback localhost endpoint to be accepted, got %v", err)
	}
	adapter.Close()
}

func TestResolveCosmosSafeDialAddressBlocksPrivateDNSByDefault(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	_, err := resolveCosmosSafeDialAddress(context.Background(), resolver, "example.com:443", false)
	if err == nil {
		t.Fatalf("expected private DNS resolution to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveCosmosSafeDialAddressBlocksCGNATDNSByDefault(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("100.64.12.8")}},
		},
	}
	_, err := resolveCosmosSafeDialAddress(context.Background(), resolver, "example.com:443", false)
	if err == nil {
		t.Fatalf("expected CGNAT DNS resolution to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveCosmosSafeDialAddressBlocksNonLocalhostLoopbackResolutionByDefault(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("127.0.0.1")}},
		},
	}
	_, err := resolveCosmosSafeDialAddress(context.Background(), resolver, "example.com:443", false)
	if err == nil {
		t.Fatalf("expected non-localhost loopback DNS resolution to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveCosmosSafeDialAddressAllowsPrivateDNSWithDangerousOverride(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	got, err := resolveCosmosSafeDialAddress(context.Background(), resolver, "example.com:443", true)
	if err != nil {
		t.Fatalf("expected dangerous private-endpoint override to allow private DNS, got %v", err)
	}
	if got != "10.0.0.6:443" {
		t.Fatalf("unexpected dial address: %s", got)
	}
}

func TestResolveCosmosSafeDialAddressBlocksLiteralCGNATByDefault(t *testing.T) {
	_, err := resolveCosmosSafeDialAddress(context.Background(), nil, "100.64.12.8:443", false)
	if err == nil {
		t.Fatalf("expected literal CGNAT endpoint to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveCosmosSafeDialAddressAllowsLiteralLoopback(t *testing.T) {
	got, err := resolveCosmosSafeDialAddress(context.Background(), nil, "127.0.0.1:1317", false)
	if err != nil {
		t.Fatalf("expected literal loopback to be allowed, got %v", err)
	}
	if got != "127.0.0.1:1317" {
		t.Fatalf("unexpected dial address: %s", got)
	}
}

func TestResolveCosmosSafeDialAddressRejectsZoneHost(t *testing.T) {
	_, err := resolveCosmosSafeDialAddress(context.Background(), nil, "[fe80::1%eth0]:443", false)
	if err == nil {
		t.Fatalf("expected zone identifier host to be rejected")
	}
	if !strings.Contains(err.Error(), "zone identifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCosmosEndpointPolicyRoundTripperBlocksPrivateDestinationBeforeRoundTrip(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	called := false
	rt := &cosmosEndpointPolicyRoundTripper{
		inner: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		resolver:                      resolver,
		allowDangerousPrivateEndpoint: false,
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, err = rt.RoundTrip(req)
	if err == nil {
		t.Fatalf("expected private destination to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatalf("expected inner round tripper to remain uncalled on blocked destination")
	}
}

func TestCosmosEndpointPolicyRoundTripperBlocksCGNATDestinationBeforeRoundTrip(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("100.64.12.8")}},
		},
	}
	called := false
	rt := &cosmosEndpointPolicyRoundTripper{
		inner: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		resolver:                      resolver,
		allowDangerousPrivateEndpoint: false,
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, err = rt.RoundTrip(req)
	if err == nil {
		t.Fatalf("expected CGNAT destination to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatalf("expected inner round tripper to remain uncalled on blocked destination")
	}
}

func TestCosmosEndpointPolicyRoundTripperAllowsDangerousOverride(t *testing.T) {
	resolver := stubCosmosOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	called := false
	rt := &cosmosEndpointPolicyRoundTripper{
		inner: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		resolver:                      resolver,
		allowDangerousPrivateEndpoint: true,
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected dangerous override to allow request, got %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if !called {
		t.Fatalf("expected inner round tripper to be called")
	}
}

func TestCosmosAdapterHealthRejectsRedirectResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Location", "/health-ok")
			w.WriteHeader(http.StatusFound)
		case "/health-ok":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	err = adapter.Health(context.Background())
	if err == nil {
		t.Fatalf("expected health redirect response to fail when redirects are disabled")
	}
	if !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("expected status 302 error, got %v", err)
	}
}

func TestNewCosmosAdapterDisablesProxyFromEnvironmentByDefault(t *testing.T) {
	t.Setenv(cosmosAllowProxyFromEnvConfigName, "")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18080")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18080")

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://127.0.0.1:9999",
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	policyRT, ok := adapter.client.Transport.(*cosmosEndpointPolicyRoundTripper)
	if !ok || policyRT == nil {
		t.Fatalf("expected cosmos endpoint policy round tripper, got %T", adapter.client.Transport)
	}
	transport, ok := policyRT.inner.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected wrapped *http.Transport, got %T", policyRT.inner)
	}
	if transport.Proxy != nil {
		t.Fatalf("expected proxy function to be nil by default")
	}
}

func TestNewCosmosAdapterAllowsProxyFromEnvironmentWithExplicitOverride(t *testing.T) {
	t.Setenv(cosmosAllowProxyFromEnvConfigName, "1")

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://127.0.0.1:9999",
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	policyRT, ok := adapter.client.Transport.(*cosmosEndpointPolicyRoundTripper)
	if !ok || policyRT == nil {
		t.Fatalf("expected cosmos endpoint policy round tripper, got %T", adapter.client.Transport)
	}
	transport, ok := policyRT.inner.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected wrapped *http.Transport, got %T", policyRT.inner)
	}
	if transport.Proxy == nil {
		t.Fatalf("expected proxy function to be configured when override is enabled")
	}
}

func TestCosmosAdapterUsesBearerAuthAcrossModes(t *testing.T) {
	const (
		token              = "adapter-auth-token"
		expectedAuthHeader = "Bearer " + token
		rewardID           = "rew-auth-1"
		rewardQueryPath    = "/x/vpnrewards/distributions/dist:" + rewardID
	)

	runMode := func(t *testing.T, cfg CosmosAdapterConfig, expectedSubmitPath string) {
		t.Helper()

		healthAuthCh := make(chan string, 1)
		submitAuthCh := make(chan string, 1)
		queryAuthCh := make(chan string, 1)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != expectedAuthHeader {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/health":
				select {
				case healthAuthCh <- authHeader:
				default:
				}
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodPost && r.URL.Path == expectedSubmitPath:
				select {
				case submitAuthCh <- authHeader:
				default:
				}
				if expectedSubmitPath == "/cosmos/tx/v1beta1/txs" {
					writeSignedTxSuccessResponse(w)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			case r.Method == http.MethodGet && r.URL.Path == rewardQueryPath:
				select {
				case queryAuthCh <- authHeader:
				default:
				}
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		cfg.Endpoint = srv.URL
		cfg.APIKey = token
		adapter, err := NewCosmosAdapter(cfg)
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		if err := adapter.Health(context.Background()); err != nil {
			t.Fatalf("Health expected nil error, got %v", err)
		}
		select {
		case got := <-healthAuthCh:
			if got != expectedAuthHeader {
				t.Fatalf("health auth mismatch: got %q", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for health auth assertion")
		}

		if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
			RewardID:          rewardID,
			ProviderSubjectID: "provider-auth-1",
			SessionID:         "sess-auth-1",
			TrafficProofRef:   "obj://traffic-proof/" + rewardID,
			RewardMicros:      100,
			Currency:          "USD",
		}); err != nil {
			t.Fatalf("SubmitRewardIssue: %v", err)
		}
		select {
		case got := <-submitAuthCh:
			if got != expectedAuthHeader {
				t.Fatalf("submit auth mismatch: got %q", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for submit auth assertion")
		}

		ok, err := adapter.HasRewardIssue(context.Background(), rewardID)
		if err != nil {
			t.Fatalf("HasRewardIssue expected nil error, got %v", err)
		}
		if !ok {
			t.Fatalf("HasRewardIssue expected true")
		}
		select {
		case got := <-queryAuthCh:
			if got != expectedAuthHeader {
				t.Fatalf("query auth mismatch: got %q", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for query auth assertion")
		}
	}

	t.Run("http_mode", func(t *testing.T) {
		runMode(t, CosmosAdapterConfig{
			QueueSize:   8,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		}, "/x/vpnrewards/issues")
	})

	t.Run("signed_tx_mode", func(t *testing.T) {
		runMode(t, CosmosAdapterConfig{
			QueueSize:       8,
			MaxRetries:      1,
			BaseBackoff:     5 * time.Millisecond,
			SubmitMode:      CosmosSubmitModeSignedTx,
			SignedTxChainID: "tdpn-test-1",
			SignedTxSigner:  "auth-signer-1",
			SignedTxSecret:  "auth-secret-1",
		}, "/cosmos/tx/v1beta1/txs")
	})
}

func TestCosmosAdapterSubmitRewardIssueRequiresObjectiveTrafficProof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("SubmitRewardIssue should reject missing proof before HTTP write, got %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:   srv.URL,
		QueueSize:  1,
		MaxRetries: 1,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	for _, tc := range []struct {
		name string
		ref  string
	}{
		{name: "missing"},
		{name: "hash-only", ref: testSHA256Ref("cosmos-reward-proof-sha-only")},
		{name: "legacy", ref: "manual-note://cosmos-reward-proof"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
				RewardID:          "rew-cosmos-proof-required-" + tc.name,
				ProviderSubjectID: "provider-cosmos-proof-required",
				SessionID:         "sess-cosmos-proof-required",
				TrafficProofRef:   tc.ref,
				RewardMicros:      100,
				Currency:          "TDPNC",
			})
			if err == nil || !strings.Contains(err.Error(), "obj:// traffic_proof_ref") {
				t.Fatalf("expected objective proof requirement error, got %v", err)
			}
		})
	}
}

func TestCosmosAdapterSubmitWithRetryTransientEventuallySucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  5,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	err = adapter.submitWithRetry(context.Background(), cosmosQueuedOperation{
		path: "/x/vpnrewards/issues",
		payload: RewardIssue{
			RewardID:          "rew-retry-direct-1",
			ProviderSubjectID: "provider-1",
			SessionID:         "sess-1",
			RewardMicros:      100,
			Currency:          "USD",
		},
		idempotencyKey: "reward:rew-retry-direct-1",
	})
	if err != nil {
		t.Fatalf("submitWithRetry expected success, got %v", err)
	}

	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected exactly 3 attempts (2 transient failures + success), got %d", got)
	}
}

func TestCosmosAdapterSubmitWithRetryRespectsContextDeadline(t *testing.T) {
	var attempts int32

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://127.0.0.1:1",
		QueueSize:   8,
		MaxRetries:  100,
		BaseBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	adapter.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			return nil, errors.New("transient dial error")
		}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = adapter.submitWithRetry(ctx, cosmosQueuedOperation{
		path: "/x/vpnbilling/settlements",
		payload: SessionSettlement{
			SettlementID: "set-ctx-deadline-1",
			SessionID:    "sess-ctx-deadline-1",
		},
		idempotencyKey: "settlement:set-ctx-deadline-1",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("submitWithRetry expected context deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("submitWithRetry took too long after context deadline: %s", elapsed)
	}
	if got := atomic.LoadInt32(&attempts); got < 2 || got > 4 {
		t.Fatalf("unexpected retry attempts under deadline; got %d", got)
	}
}

func TestCosmosAdapterSubmitsSettlementWithIdempotencyKey(t *testing.T) {
	type seenRequest struct {
		path string
		key  string
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seenRequest{
			path: r.URL.Path,
			key:  r.Header.Get("Idempotency-Key"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	ref, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID: "set-123",
		SessionID:    "sess-123",
	})
	if err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}
	if ref != "settlement:set-123" {
		t.Fatalf("unexpected ref id %q", ref)
	}

	select {
	case got := <-seenCh:
		if got.path != "/x/vpnbilling/settlements" {
			t.Fatalf("unexpected path %q", got.path)
		}
		if got.key != "settlement:set-123" {
			t.Fatalf("unexpected idempotency key %q", got.key)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued submit")
	}
}

func TestCosmosAdapterSubmitsFundReservationWithIdempotencyKey(t *testing.T) {
	type seenRequest struct {
		path string
		key  string
		body []byte
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seenCh <- seenRequest{
			path: r.URL.Path,
			key:  r.Header.Get("Idempotency-Key"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ref, err := adapter.SubmitFundReservation(context.Background(), FundReservation{
		ReservationID: "res-123",
		SessionID:     "sess-123",
		SubjectID:     "subject-123",
		AmountMicros:  250,
		Currency:      "uusdc",
		CreatedAt:     createdAt,
	})
	if err != nil {
		t.Fatalf("SubmitFundReservation: %v", err)
	}
	if ref != "reservation:res-123" {
		t.Fatalf("unexpected ref id %q", ref)
	}

	select {
	case got := <-seenCh:
		if got.path != "/x/vpnbilling/reservations" {
			t.Fatalf("unexpected path %q", got.path)
		}
		if got.key != "reservation:res-123" {
			t.Fatalf("unexpected idempotency key %q", got.key)
		}
		var payload struct {
			ReservationID string    `json:"ReservationID"`
			SessionID     string    `json:"SessionID"`
			SubjectID     string    `json:"SubjectID"`
			AmountMicros  int64     `json:"AmountMicros"`
			Currency      string    `json:"Currency"`
			CreatedAt     time.Time `json:"CreatedAt"`
			Status        string    `json:"Status"`
		}
		if err := json.Unmarshal(got.body, &payload); err != nil {
			t.Fatalf("unmarshal fund reservation payload: %v", err)
		}
		if payload.ReservationID != "res-123" ||
			payload.SessionID != "sess-123" ||
			payload.SubjectID != "subject-123" ||
			payload.AmountMicros != 250 ||
			payload.Currency != "uusdc" ||
			!payload.CreatedAt.Equal(createdAt) ||
			payload.Status != string(OperationStatusPending) {
			t.Fatalf("unexpected fund reservation payload: %#v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued submit")
	}
}

func TestCosmosAdapterTrustedHTTPWritesFinalFundReservationStatus(t *testing.T) {
	seenCh := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seenCh <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		FinalityAuthToken:     "finality-token",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SubmitFundReservation(context.Background(), FundReservation{
		ReservationID: "res-trusted-final",
		SessionID:     "sess-trusted-final",
		SubjectID:     "subject-trusted-final",
		AmountMicros:  250,
		Currency:      "uusdc",
		Status:        OperationStatusSubmitted,
	})
	if err != nil {
		t.Fatalf("SubmitFundReservation: %v", err)
	}

	select {
	case body := <-seenCh:
		var payload struct {
			Status string `json:"Status"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal fund reservation payload: %v", err)
		}
		if payload.Status != string(OperationStatusSubmitted) {
			t.Fatalf("trusted HTTP fund reservation status=%q want submitted; bridge finality must not promote status locally", payload.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued submit")
	}
}

func TestCosmosAdapterTrustedHTTPFundReservationRoundTripsBridgeFinality(t *testing.T) {
	statuses := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Status string `json:"Status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		statuses <- payload.Status
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		FinalityAuthToken:     "finality-token",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SubmitFundReservation(context.Background(), FundReservation{
		ReservationID: "res-bridge-finality",
		SessionID:     "sess-bridge-finality",
		SubjectID:     "subject-bridge-finality",
		AmountMicros:  250,
		Currency:      "uusdc",
		Status:        OperationStatusSubmitted,
	})
	if err != nil {
		t.Fatalf("SubmitFundReservation: %v", err)
	}

	select {
	case got := <-statuses:
		if got != string(OperationStatusSubmitted) {
			t.Fatalf("trusted bridge reservation step status=%q want submitted", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for trusted bridge reservation step %s", OperationStatusSubmitted)
	}
	select {
	case got := <-statuses:
		t.Fatalf("trusted bridge reservation unexpectedly promoted local status to %q", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCosmosAdapterTrustedHTTPWritesFinalRewardIssueStatus(t *testing.T) {
	seenCh := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seenCh <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		FinalityAuthToken:     "finality-token",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-trusted-final",
		ProviderSubjectID: "provider-trusted-final",
		SessionID:         "sess-trusted-final",
		TrafficProofRef:   "obj://traffic-proof/rew-trusted-final",
		RewardMicros:      250,
		Currency:          "uusdc",
		Status:            OperationStatusSubmitted,
	})
	if err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	select {
	case body := <-seenCh:
		var payload struct {
			Status string `json:"Status"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal reward issue payload: %v", err)
		}
		if payload.Status != string(OperationStatusSubmitted) {
			t.Fatalf("trusted HTTP reward issue status=%q want submitted; bridge finality must not promote status locally", payload.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued submit")
	}
}

func TestCosmosAdapterRejectsFinalRewardIssueWithoutTrustedHTTPFinality(t *testing.T) {
	seenCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-final-without-trust",
		ProviderSubjectID: "provider-final-without-trust",
		SessionID:         "sess-final-without-trust",
		TrafficProofRef:   "obj://traffic-proof/rew-final-without-trust",
		RewardMicros:      250,
		Currency:          "uusdc",
		Status:            OperationStatusConfirmed,
	})
	if err == nil || !strings.Contains(err.Error(), "requires trusted bridge finality") {
		t.Fatalf("expected trusted finality rejection, got %v", err)
	}
	select {
	case <-seenCh:
		t.Fatal("final reward issue should not be submitted without trusted bridge finality")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCosmosAdapterRejectsFinalRewardIssueWhenTokenConfiguredButTrustDisabled(t *testing.T) {
	seenCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:          srv.URL,
		APIKey:            "bridge-token",
		FinalityAuthToken: "finality-token",
		QueueSize:         8,
		MaxRetries:        1,
		BaseBackoff:       5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-final-token-without-trust",
		ProviderSubjectID: "provider-final-token-without-trust",
		SessionID:         "sess-final-token-without-trust",
		TrafficProofRef:   "obj://traffic-proof/rew-final-token-without-trust",
		RewardMicros:      250,
		Currency:          "uusdc",
		Status:            OperationStatusConfirmed,
	})
	if err == nil || !strings.Contains(err.Error(), "requires trusted bridge finality") {
		t.Fatalf("expected trusted finality rejection, got %v", err)
	}
	select {
	case <-seenCh:
		t.Fatal("final reward issue should not be submitted when trust is disabled")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestNewCosmosAdapterRejectsTrustedBridgeFinalityWithoutToken(t *testing.T) {
	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              "http://127.0.0.1:1317",
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		FinalityAuthToken:     " \t ",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "trusted bridge finality requires FinalityAuthToken") {
		t.Fatalf("expected trusted bridge finality token validation error, got %v", err)
	}
}

func TestCosmosAdapterRejectsUnknownWriteStatusesBeforeEnqueue(t *testing.T) {
	seenCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	invalidStatus := OperationStatus("mystery")
	cases := []struct {
		name string
		call func() (string, error)
	}{
		{
			name: "fund reservation",
			call: func() (string, error) {
				return adapter.SubmitFundReservation(context.Background(), FundReservation{
					ReservationID: "res-invalid-status",
					SessionID:     "sess-invalid-status",
					SubjectID:     "subject-invalid-status",
					AmountMicros:  100,
					Currency:      "uusdc",
					Status:        invalidStatus,
				})
			},
		},
		{
			name: "session settlement",
			call: func() (string, error) {
				return adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
					SettlementID:  "set-invalid-status",
					ReservationID: "res-invalid-status",
					SessionID:     "sess-invalid-status",
					SubjectID:     "subject-invalid-status",
					ChargedMicros: 100,
					Currency:      "uusdc",
					Status:        invalidStatus,
				})
			},
		},
		{
			name: "reward issue",
			call: func() (string, error) {
				return adapter.SubmitRewardIssue(context.Background(), RewardIssue{
					RewardID:          "reward-invalid-status",
					ProviderSubjectID: "provider-invalid-status",
					SessionID:         "sess-invalid-status",
					TrafficProofRef:   "obj://traffic-proof/reward-invalid-status",
					RewardMicros:      100,
					Currency:          "uusdc",
					Status:            invalidStatus,
				})
			},
		},
		{
			name: "sponsor reservation",
			call: func() (string, error) {
				return adapter.SubmitSponsorReservation(context.Background(), SponsorCreditReservation{
					ReservationID: "sres-invalid-status",
					SponsorID:     "sponsor-invalid-status",
					SubjectID:     "subject-invalid-status",
					SessionID:     "sess-invalid-status",
					AmountMicros:  100,
					Currency:      "uusdc",
					Status:        invalidStatus,
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := tc.call()
			if err == nil || !strings.Contains(err.Error(), `invalid cosmos operation status "mystery"`) {
				t.Fatalf("expected invalid status rejection, got ref=%q err=%v", ref, err)
			}
		})
	}

	select {
	case path := <-seenCh:
		t.Fatalf("invalid status should not enqueue HTTP write, saw path %q", path)
	case <-time.After(100 * time.Millisecond):
	}
}

type cosmosScopedHeaderSeenRequest struct {
	path          string
	auth          string
	proofAuth     string
	finalityAuth  string
	payloadStatus string
}

func TestCosmosAdapterSetsScopedBridgeHeaders(t *testing.T) {
	seenCh := make(chan cosmosScopedHeaderSeenRequest, 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Status string `json:"Status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		seenCh <- cosmosScopedHeaderSeenRequest{
			path:          r.URL.Path,
			auth:          r.Header.Get("Authorization"),
			proofAuth:     r.Header.Get(cosmosRewardProofAuthorizationHeader),
			finalityAuth:  r.Header.Get(cosmosFinalityAuthorizationHeader),
			payloadStatus: payload.Status,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		RewardProofAuthToken:  "proof-token",
		FinalityAuthToken:     "finality-token",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardProof(context.Background(), RewardProofRecord{
		ProofPath:         "traffic-proof/scoped-1",
		TrafficProofRef:   "obj://traffic-proof/scoped-1",
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-scoped-1",
		ProviderSubjectID: "provider-scoped-1",
		SessionID:         "sess-scoped-1",
		RewardMicros:      100,
		Currency:          "uusdc",
		IssuedAt:          time.Now().UTC(),
		Verified:          true,
		VerifierID:        "proof-verifier",
		VerifiedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SubmitRewardProof: %v", err)
	}
	proofReq := waitSeenCosmosScopedRequest(t, seenCh)
	if proofReq.path != "/x/vpnrewards/proofs" || proofReq.auth != "Bearer bridge-token" || proofReq.proofAuth != "Bearer proof-token" {
		t.Fatalf("unexpected proof scoped headers: %+v", proofReq)
	}

	if _, err := adapter.SubmitFundReservation(context.Background(), FundReservation{
		ReservationID: "res-scoped-1",
		SessionID:     "sess-scoped-1",
		SubjectID:     "subject-scoped-1",
		AmountMicros:  250,
		Currency:      "uusdc",
		Status:        OperationStatusSubmitted,
	}); err != nil {
		t.Fatalf("SubmitFundReservation: %v", err)
	}
	reservationReq := waitSeenCosmosScopedRequest(t, seenCh)
	if reservationReq.path != "/x/vpnbilling/reservations" || reservationReq.payloadStatus != string(OperationStatusSubmitted) || reservationReq.finalityAuth != "" {
		t.Fatalf("unexpected reservation scoped headers: %+v", reservationReq)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "reward-scoped-submitted",
		ProviderSubjectID: "provider-scoped-submitted",
		SessionID:         "sess-scoped-submitted",
		TrafficProofRef:   "obj://traffic-proof/reward-scoped-submitted",
		RewardMicros:      100,
		Currency:          "uusdc",
		Status:            OperationStatusSubmitted,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue submitted: %v", err)
	}
	submittedRewardReq := waitSeenCosmosScopedRequest(t, seenCh)
	if submittedRewardReq.path != "/x/vpnrewards/issues" ||
		submittedRewardReq.payloadStatus != string(OperationStatusSubmitted) ||
		submittedRewardReq.finalityAuth != "" {
		t.Fatalf("unexpected submitted reward scoped headers: %+v", submittedRewardReq)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "reward-scoped-confirmed",
		ProviderSubjectID: "provider-scoped-confirmed",
		SessionID:         "sess-scoped-confirmed",
		TrafficProofRef:   "obj://traffic-proof/reward-scoped-confirmed",
		RewardMicros:      100,
		Currency:          "uusdc",
		Status:            OperationStatusConfirmed,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue confirmed: %v", err)
	}
	confirmedRewardReq := waitSeenCosmosScopedRequest(t, seenCh)
	if confirmedRewardReq.path != "/x/vpnrewards/issues" ||
		confirmedRewardReq.payloadStatus != string(OperationStatusConfirmed) ||
		confirmedRewardReq.finalityAuth != "Bearer finality-token" {
		t.Fatalf("unexpected confirmed reward scoped headers: %+v", confirmedRewardReq)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "reward-scoped-failed",
		ProviderSubjectID: "provider-scoped-failed",
		SessionID:         "sess-scoped-failed",
		TrafficProofRef:   "obj://traffic-proof/reward-scoped-failed",
		RewardMicros:      100,
		Currency:          "uusdc",
		Status:            OperationStatusFailed,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue failed: %v", err)
	}
	failedRewardReq := waitSeenCosmosScopedRequest(t, seenCh)
	if failedRewardReq.path != "/x/vpnrewards/issues" ||
		failedRewardReq.payloadStatus != string(OperationStatusFailed) ||
		failedRewardReq.finalityAuth != "Bearer finality-token" {
		t.Fatalf("unexpected failed reward scoped headers: %+v", failedRewardReq)
	}
}

func waitSeenCosmosScopedRequest(t *testing.T, ch <-chan cosmosScopedHeaderSeenRequest) cosmosScopedHeaderSeenRequest {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scoped cosmos request")
		return cosmosScopedHeaderSeenRequest{}
	}
}

func TestCosmosAdapterBridgePayloadsUseStrictCompatibleShapes(t *testing.T) {
	type reservationPayload struct {
		ReservationID string    `json:"ReservationID"`
		SessionID     string    `json:"SessionID"`
		SubjectID     string    `json:"SubjectID"`
		AmountMicros  int64     `json:"AmountMicros"`
		Currency      string    `json:"Currency"`
		CreatedAt     time.Time `json:"CreatedAt"`
		Status        string    `json:"Status"`
	}
	type settlementPayload struct {
		SettlementID  string    `json:"SettlementID"`
		ReservationID string    `json:"ReservationID"`
		SessionID     string    `json:"SessionID"`
		SubjectID     string    `json:"SubjectID"`
		ChargedMicros int64     `json:"ChargedMicros"`
		Currency      string    `json:"Currency"`
		SettledAt     time.Time `json:"SettledAt"`
		Status        string    `json:"Status"`
	}
	type rewardPayload struct {
		RewardID              string    `json:"RewardID"`
		ProviderSubjectID     string    `json:"ProviderSubjectID"`
		SessionID             string    `json:"SessionID"`
		SettlementReferenceID string    `json:"SettlementReferenceID"`
		TrafficProofRef       string    `json:"TrafficProofRef"`
		PayoutPeriodStart     time.Time `json:"PayoutPeriodStart"`
		PayoutPeriodEnd       time.Time `json:"PayoutPeriodEnd"`
		RewardMicros          int64     `json:"RewardMicros"`
		Currency              string    `json:"Currency"`
		IssuedAt              time.Time `json:"IssuedAt"`
		Status                string    `json:"Status"`
	}
	type rewardProofPayload struct {
		ProofPath         string    `json:"ProofPath"`
		TrafficProofRef   string    `json:"TrafficProofRef"`
		TrustContract     string    `json:"TrustContract"`
		RewardID          string    `json:"RewardID"`
		ProviderSubjectID string    `json:"ProviderSubjectID"`
		SessionID         string    `json:"SessionID"`
		PayoutPeriodStart time.Time `json:"PayoutPeriodStart"`
		PayoutPeriodEnd   time.Time `json:"PayoutPeriodEnd"`
		RewardMicros      int64     `json:"RewardMicros"`
		Currency          string    `json:"Currency"`
		IssuedAt          time.Time `json:"IssuedAt"`
		Verified          bool      `json:"Verified"`
		VerifierID        string    `json:"VerifierID"`
		VerifiedAt        time.Time `json:"VerifiedAt"`
	}
	type sponsorPayload struct {
		ReservationID string    `json:"ReservationID"`
		SponsorID     string    `json:"SponsorID"`
		SubjectID     string    `json:"SubjectID"`
		SessionID     string    `json:"SessionID"`
		AmountMicros  int64     `json:"AmountMicros"`
		Currency      string    `json:"Currency"`
		CreatedAt     time.Time `json:"CreatedAt"`
		ExpiresAt     time.Time `json:"ExpiresAt"`
		Status        string    `json:"Status"`
	}
	type slashPayload struct {
		EvidenceID    string    `json:"EvidenceID"`
		SubjectID     string    `json:"SubjectID"`
		SessionID     string    `json:"SessionID"`
		ViolationType string    `json:"ViolationType"`
		EvidenceRef   string    `json:"EvidenceRef"`
		SlashMicros   int64     `json:"SlashMicros"`
		Currency      string    `json:"Currency"`
		ObservedAt    time.Time `json:"ObservedAt"`
		Status        string    `json:"Status"`
	}

	seenCh := make(chan string, 8)
	decodeErrCh := make(chan error, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var err error
		switch r.URL.Path {
		case "/x/vpnbilling/reservations":
			var payload reservationPayload
			err = decoder.Decode(&payload)
		case "/x/vpnbilling/settlements":
			var payload settlementPayload
			err = decoder.Decode(&payload)
		case "/x/vpnrewards/issues":
			var payload rewardPayload
			err = decoder.Decode(&payload)
		case "/x/vpnrewards/proofs":
			var payload rewardProofPayload
			err = decoder.Decode(&payload)
		case "/x/vpnsponsor/reservations":
			var payload sponsorPayload
			err = decoder.Decode(&payload)
		case "/x/vpnslashing/evidence":
			var payload slashPayload
			err = decoder.Decode(&payload)
		default:
			err = fmt.Errorf("unexpected path %q", r.URL.Path)
		}
		if err == nil {
			var trailing json.RawMessage
			if decodeTrailingErr := decoder.Decode(&trailing); decodeTrailingErr != nil && !errors.Is(decodeTrailingErr, io.EOF) {
				err = fmt.Errorf("trailing decode error: %w", decodeTrailingErr)
			}
		}
		if err != nil {
			select {
			case decodeErrCh <- err:
			default:
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case seenCh <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:             srv.URL,
		APIKey:               "bridge-token",
		RewardProofAuthToken: "proof-token",
		QueueSize:            8,
		MaxRetries:           1,
		BaseBackoff:          5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	now := time.Now().UTC()
	if _, err := adapter.SubmitFundReservation(context.Background(), FundReservation{
		ReservationID: "res-shape-1",
		SessionID:     "sess-shape-1",
		SubjectID:     "subject-shape-1",
		AmountMicros:  101,
		Currency:      "TDPNC",
		CreatedAt:     now,
		Status:        OperationStatusPending,
	}); err != nil {
		t.Fatalf("SubmitFundReservation: %v", err)
	}
	if _, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID:  "set-shape-1",
		ReservationID: "res-shape-1",
		SessionID:     "sess-shape-1",
		SubjectID:     "subject-shape-1",
		ChargedMicros: 101,
		Currency:      "TDPNC",
		SettledAt:     now,
		Status:        OperationStatusSubmitted,
	}); err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}
	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:              "rew-shape-1",
		ProviderSubjectID:     "provider-shape-1",
		SessionID:             "sess-shape-1",
		SettlementReferenceID: "set-shape-1",
		TrafficProofRef:       "obj://traffic-proof/rew-shape-1",
		PayoutPeriodStart:     time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC),
		PayoutPeriodEnd:       time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC),
		RewardMicros:          17,
		Currency:              "TDPNC",
		IssuedAt:              now,
		Status:                OperationStatusSubmitted,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}
	if _, err := adapter.SubmitRewardProof(context.Background(), RewardProofRecord{
		ProofPath:         "traffic-proof/rew-shape-1",
		TrafficProofRef:   "obj://traffic-proof/rew-shape-1",
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "rew-shape-1",
		ProviderSubjectID: "provider-shape-1",
		SessionID:         "sess-shape-1",
		PayoutPeriodStart: time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC),
		PayoutPeriodEnd:   time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC),
		RewardMicros:      17,
		Currency:          "TDPNC",
		IssuedAt:          now,
		Verified:          true,
		VerifierID:        "strict-shape-verifier",
		VerifiedAt:        now,
	}); err != nil {
		t.Fatalf("SubmitRewardProof: %v", err)
	}
	if _, err := adapter.SubmitSponsorReservation(context.Background(), SponsorCreditReservation{
		ReservationID: "res-shape-1",
		SponsorID:     "sponsor-shape-1",
		SubjectID:     "app-shape-1",
		SessionID:     "sess-shape-2",
		AmountMicros:  42,
		Currency:      "TDPNC",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Minute),
		Status:        OperationStatusPending,
	}); err != nil {
		t.Fatalf("SubmitSponsorReservation: %v", err)
	}
	if _, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
		EvidenceID:    "evidence-shape-1",
		SubjectID:     "provider-shape-1",
		SessionID:     "sess-shape-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:2935ad7b7d9dec338fd099d83ddcfc1a53c3fc35929197eeb6826db0aa4c684e",
		SlashMicros:   99,
		Currency:      "TDPNC",
		ObservedAt:    now,
		Status:        OperationStatusSubmitted,
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	expectedPaths := map[string]bool{
		"/x/vpnbilling/reservations": true,
		"/x/vpnbilling/settlements":  true,
		"/x/vpnrewards/issues":       true,
		"/x/vpnrewards/proofs":       true,
		"/x/vpnsponsor/reservations": true,
		"/x/vpnslashing/evidence":    true,
	}
	seen := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(seen) < len(expectedPaths) {
		select {
		case err := <-decodeErrCh:
			t.Fatalf("strict payload decode failed: %v", err)
		case path := <-seenCh:
			seen[path] = true
		case <-deadline:
			t.Fatalf("timed out waiting for strict payload submits (seen=%v)", seen)
		}
	}
	for path := range expectedPaths {
		if !seen[path] {
			t.Fatalf("missing expected submitted path %q (seen=%v)", path, seen)
		}
	}
}

func TestCosmosAdapterRetriesTransientFailure(t *testing.T) {
	var attempts int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  2,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		TrafficProofRef:   "obj://traffic-proof/rew-1",
		RewardMicros:      100,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for retry success")
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Fatalf("expected at least two attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestCosmosAdapterDoesNotRetryNonRetryable4xx(t *testing.T) {
	var attempts int32
	firstAttemptCh := make(chan struct{}, 1)
	secondAttemptCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			select {
			case firstAttemptCh <- struct{}{}:
			default:
			}
		}
		if n == 2 {
			select {
			case secondAttemptCh <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  3,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-4xx-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		TrafficProofRef:   "obj://traffic-proof/rew-4xx-1",
		RewardMicros:      100,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	select {
	case <-firstAttemptCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first attempt")
	}

	select {
	case <-secondAttemptCh:
		t.Fatalf("unexpected retry for non-retryable 4xx response")
	case <-time.After(200 * time.Millisecond):
	}

	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly one attempt, got %d", got)
	}
}

func TestCosmosAdapterNonRetryableFailuresBecomeDeferredNonReplayable(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnrewards/issues" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  3,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-nonretry-deferred-1",
		ProviderSubjectID: "provider-nonretry-deferred-1",
		SessionID:         "sess-nonretry-deferred-1",
		TrafficProofRef:   "obj://traffic-proof/rew-nonretry-deferred-1",
		RewardMicros:      100,
		Currency:          "TDPNC",
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 1
	}, "non-retryable deferred entry")

	entry, ok := adapter.deferredOperationByID("reward:rew-nonretry-deferred-1")
	if !ok {
		t.Fatalf("expected deferred entry for reward:rew-nonretry-deferred-1")
	}
	if entry.replayable {
		t.Fatalf("expected non-retryable deferred entry to be non-replayable")
	}
	if entry.attempts != 1 {
		t.Fatalf("expected one attempt for non-retryable 4xx, got %d", entry.attempts)
	}
	if !strings.Contains(entry.lastError, "status 400") {
		t.Fatalf("expected deferred last error to include status 400, got %q", entry.lastError)
	}

	attemptsAfterDefer := atomic.LoadInt32(&attempts)
	time.Sleep(120 * time.Millisecond)
	if got := atomic.LoadInt32(&attempts); got != attemptsAfterDefer {
		t.Fatalf("expected no replay attempts for non-replayable deferred entry, got %d->%d", attemptsAfterDefer, got)
	}
	if got := adapter.deferredOperationCount(); got != 1 {
		t.Fatalf("expected deferred entry to remain queued for manual intervention, got count=%d", got)
	}
}

func TestCosmosAdapterReplayableDeferredBecomesNonReplayableAfterReplay4xx(t *testing.T) {
	var attempts int32
	var replayPhase atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnrewards/issues" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&attempts, 1)
		if replayPhase.Load() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-replay-switch-1",
		ProviderSubjectID: "provider-replay-switch-1",
		SessionID:         "sess-replay-switch-1",
		TrafficProofRef:   "obj://traffic-proof/rew-replay-switch-1",
		RewardMicros:      100,
		Currency:          "TDPNC",
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		entry, ok := adapter.deferredOperationByID("reward:rew-replay-switch-1")
		return ok && entry.replayable && entry.attempts >= 1 && strings.Contains(entry.lastError, "status 503")
	}, "retryable deferred entry to appear after initial 503")

	replayPhase.Store(true)

	waitForCondition(t, 2*time.Second, func() bool {
		entry, ok := adapter.deferredOperationByID("reward:rew-replay-switch-1")
		return ok && !entry.replayable && entry.attempts >= 2 && strings.Contains(entry.lastError, "status 400")
	}, "deferred replay to switch operation into non-replayable 4xx state")

	attemptsAfterFreeze := atomic.LoadInt32(&attempts)
	time.Sleep(120 * time.Millisecond)
	if got := atomic.LoadInt32(&attempts); got != attemptsAfterFreeze {
		t.Fatalf("expected no replay attempts after non-retryable replay result, got %d->%d", attemptsAfterFreeze, got)
	}
	if got := adapter.deferredOperationCount(); got != 1 {
		t.Fatalf("expected deferred backlog entry to remain for manual intervention, got count=%d", got)
	}
}

func TestCosmosAdapterRetries429And503(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
	}{
		{name: "too_many_requests", statusCode: http.StatusTooManyRequests},
		{name: "service_unavailable", statusCode: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts int32
			doneCh := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := atomic.AddInt32(&attempts, 1)
				if n == 1 {
					w.WriteHeader(tc.statusCode)
					return
				}
				w.WriteHeader(http.StatusOK)
				select {
				case doneCh <- struct{}{}:
				default:
				}
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:    srv.URL,
				QueueSize:   8,
				MaxRetries:  2,
				BaseBackoff: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			if _, err := adapter.SubmitSponsorReservation(context.Background(), SponsorCreditReservation{
				ReservationID: "res-1",
				SponsorID:     "sp-1",
				SessionID:     "sess-1",
				AmountMicros:  100,
				Currency:      "USD",
			}); err != nil {
				t.Fatalf("SubmitSponsorReservation: %v", err)
			}

			select {
			case <-doneCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for retry success")
			}
			if got := atomic.LoadInt32(&attempts); got < 2 {
				t.Fatalf("expected at least two attempts, got %d", got)
			}
		})
	}
}

func TestCosmosAdapterConfirmationQueryPathMappings(t *testing.T) {
	seenPathCh := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPathCh <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if ok, err := adapter.HasSessionSettlement(context.Background(), "set-1"); err != nil || !ok {
		t.Fatalf("HasSessionSettlement expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnbilling/settlements/set-1" {
		t.Fatalf("unexpected settlement query path %q", got)
	}

	if ok, err := adapter.HasRewardIssue(context.Background(), "rew-1"); err != nil || !ok {
		t.Fatalf("HasRewardIssue expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnrewards/distributions/dist:rew-1" {
		t.Fatalf("unexpected reward query path %q", got)
	}

	if ok, err := adapter.HasSponsorReservation(context.Background(), "sres-1"); err != nil || !ok {
		t.Fatalf("HasSponsorReservation expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnsponsor/delegations/sres-1" {
		t.Fatalf("unexpected sponsor query path %q", got)
	}

	if ok, err := adapter.HasSlashEvidence(context.Background(), "ev-1"); err != nil || !ok {
		t.Fatalf("HasSlashEvidence expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnslashing/evidence/ev-1" {
		t.Fatalf("unexpected slash query path %q", got)
	}
}

func TestCosmosAdapterConfirmationStatusQueriesDecodeFinality(t *testing.T) {
	seenPathCh := make(chan string, 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPathCh <- r.URL.Path
		switch r.URL.Path {
		case "/x/vpnbilling/settlements/set-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"settlement": map[string]any{
					"SettlementID":    "set-1",
					"ReservationID":   "res-set-1",
					"SessionID":       "sess-set-1",
					"SubjectID":       "subject-set-1",
					"BilledAmount":    "101",
					"AssetDenom":      "uusdc",
					"SettledAtUnix":   1771234567,
					"OperationState":  "confirmed",
					"SettlementNonce": "ignored",
				},
			})
		case "/x/vpnbilling/reservations/res-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"reservation": map[string]any{
					"ReservationID": "res-1",
					"Status":        "rejected",
				},
			})
		case "/x/vpnrewards/distributions/dist:rew-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"distribution": map[string]any{
					"DistributionID": "dist:rew-1",
					"Status":         "submitted",
				},
			})
		case "/x/vpnsponsor/delegations/sres-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"delegation": map[string]any{
					"ReservationID": "sres-1",
					"SponsorID":     "sponsor-1",
					"SubjectID":     "client-1",
					"SessionID":     "sess-1",
					"AmountMicros":  "202",
					"Currency":      "uusdc",
					"CreatedAtUnix": 1771234500,
					"ExpiresAtUnix": 1771239900,
					"Status":        "pending",
				},
			})
		case "/x/vpnslashing/evidence/ev-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"evidence": map[string]any{
					"EvidenceID": "ev-1",
					"Status":     "RECONCILIATION_STATUS_CONFIRMED",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if status, found, err := adapter.SessionSettlementStatus(context.Background(), "set-1"); err != nil || !found || status != OperationStatusConfirmed {
		t.Fatalf("SessionSettlementStatus got status=%s found=%v err=%v", status, found, err)
	}
	if got := <-seenPathCh; got != "/x/vpnbilling/settlements/set-1" {
		t.Fatalf("unexpected settlement status query path %q", got)
	}
	settlement, found, err := adapter.SessionSettlement(context.Background(), "set-1")
	if err != nil || !found {
		t.Fatalf("SessionSettlement found=%v err=%v", found, err)
	}
	if settlement.SettlementID != "set-1" ||
		settlement.ReservationID != "res-set-1" ||
		settlement.SessionID != "sess-set-1" ||
		settlement.SubjectID != "subject-set-1" ||
		settlement.ChargedMicros != 101 ||
		settlement.Currency != "uusdc" ||
		settlement.Status != OperationStatusConfirmed ||
		settlement.SettledAt.Unix() != 1771234567 {
		t.Fatalf("unexpected settlement material: %+v", settlement)
	}
	if got := <-seenPathCh; got != "/x/vpnbilling/settlements/set-1" {
		t.Fatalf("unexpected settlement material query path %q", got)
	}

	if status, found, err := adapter.FundReservationStatus(context.Background(), "res-1"); err != nil || !found || status != OperationStatusFailed {
		t.Fatalf("FundReservationStatus got status=%s found=%v err=%v", status, found, err)
	}
	if got := <-seenPathCh; got != "/x/vpnbilling/reservations/res-1" {
		t.Fatalf("unexpected fund reservation status query path %q", got)
	}

	if status, found, err := adapter.RewardIssueStatus(context.Background(), "rew-1"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("RewardIssueStatus got status=%s found=%v err=%v", status, found, err)
	}
	if got := <-seenPathCh; got != "/x/vpnrewards/distributions/dist:rew-1" {
		t.Fatalf("unexpected reward status query path %q", got)
	}

	if status, found, err := adapter.SponsorReservationStatus(context.Background(), "sres-1"); err != nil || !found || status != OperationStatusPending {
		t.Fatalf("SponsorReservationStatus got status=%s found=%v err=%v", status, found, err)
	}
	if got := <-seenPathCh; got != "/x/vpnsponsor/delegations/sres-1" {
		t.Fatalf("unexpected sponsor status query path %q", got)
	}
	sponsorReservation, found, err := adapter.SponsorReservation(context.Background(), "sres-1")
	if err != nil || !found {
		t.Fatalf("SponsorReservation found=%v err=%v", found, err)
	}
	if sponsorReservation.ReservationID != "sres-1" ||
		sponsorReservation.SponsorID != "sponsor-1" ||
		sponsorReservation.SubjectID != "client-1" ||
		sponsorReservation.SessionID != "sess-1" ||
		sponsorReservation.AmountMicros != 202 ||
		sponsorReservation.Currency != "UUSDC" ||
		sponsorReservation.Status != OperationStatusPending ||
		sponsorReservation.CreatedAt.Unix() != 1771234500 ||
		sponsorReservation.ExpiresAt.Unix() != 1771239900 {
		t.Fatalf("unexpected sponsor reservation material: %+v", sponsorReservation)
	}
	if got := <-seenPathCh; got != "/x/vpnsponsor/delegations/sres-1" {
		t.Fatalf("unexpected sponsor material query path %q", got)
	}

	if status, found, err := adapter.SlashEvidenceStatus(context.Background(), "ev-1"); err != nil || !found || status != OperationStatusConfirmed {
		t.Fatalf("SlashEvidenceStatus got status=%s found=%v err=%v", status, found, err)
	}
	if got := <-seenPathCh; got != "/x/vpnslashing/evidence/ev-1" {
		t.Fatalf("unexpected slash status query path %q", got)
	}
}

func TestCosmosAdapterSponsorReservationMaterialFailsClosedOnInvalidPayload(t *testing.T) {
	cases := []struct {
		name    string
		body    map[string]any
		wantErr string
	}{
		{
			name: "mismatched id",
			body: map[string]any{
				"ReservationID": "sres-other",
				"SponsorID":     "sponsor-1",
				"SubjectID":     "client-1",
				"AmountMicros":  "100",
				"Currency":      "uusdc",
				"Status":        "confirmed",
			},
			wantErr: "id mismatch",
		},
		{
			name: "missing amount",
			body: map[string]any{
				"ReservationID": "sres-invalid",
				"SponsorID":     "sponsor-1",
				"SubjectID":     "client-1",
				"Currency":      "uusdc",
				"Status":        "confirmed",
			},
			wantErr: "amount_micros > 0",
		},
		{
			name: "missing subject",
			body: map[string]any{
				"ReservationID": "sres-invalid",
				"SponsorID":     "sponsor-1",
				"AmountMicros":  "100",
				"Currency":      "uusdc",
				"Status":        "confirmed",
			},
			wantErr: "missing sponsor_id or subject_id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/x/vpnsponsor/delegations/sres-invalid" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"ok":         true,
					"delegation": tc.body,
				})
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:    srv.URL,
				QueueSize:   8,
				MaxRetries:  1,
				BaseBackoff: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			_, _, err = adapter.SponsorReservation(context.Background(), "sres-invalid")
			if err == nil {
				t.Fatalf("expected invalid sponsor reservation material to fail")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCosmosAdapterHTTPBridgeDoesNotPromoteFromRelatedFinalStates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/x/vpnbilling/settlements/set-http":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"settlement": map[string]any{
					"SettlementID":   "set-http",
					"ReservationID":  "res-http",
					"OperationState": "submitted",
				},
			})
		case "/x/vpnbilling/reservations/res-http":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"reservation": map[string]any{
					"ReservationID": "res-http",
					"Status":        "confirmed",
				},
			})
		case "/x/vpnrewards/distributions/dist:rew-http":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"distribution": map[string]any{
					"DistributionID": "dist:rew-http",
					"AccrualID":      "rew-http",
					"Status":         "submitted",
				},
			})
		case "/x/vpnrewards/accruals/rew-http":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"accrual": map[string]any{
					"AccrualID":      "rew-http",
					"OperationState": "confirmed",
				},
			})
		case "/x/vpnsponsor/delegations/sres-http":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"delegation": map[string]any{
					"ReservationID": "sres-http",
					"Status":        "pending",
				},
			})
		case "/x/vpnslashing/evidence/ev-http":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"evidence": map[string]any{
					"EvidenceID": "ev-http",
					"Status":     "submitted",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		FinalityAuthToken:     "finality-token",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if status, found, err := adapter.SessionSettlementStatus(context.Background(), "set-http"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("SessionSettlementStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.FundReservationStatus(context.Background(), "res-http"); err != nil || !found || status != OperationStatusConfirmed {
		t.Fatalf("FundReservationStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.RewardIssueStatus(context.Background(), "rew-http"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("RewardIssueStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.SponsorReservationStatus(context.Background(), "sres-http"); err != nil || !found || status != OperationStatusPending {
		t.Fatalf("SponsorReservationStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.SlashEvidenceStatus(context.Background(), "ev-http"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("SlashEvidenceStatus got status=%s found=%v err=%v", status, found, err)
	}
}

func TestCosmosAdapterTrustedHTTPRewardIssueStatusDoesNotDeriveAccrualFinality(t *testing.T) {
	seenPathCh := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPathCh <- r.URL.Path
		switch r.URL.Path {
		case "/x/vpnrewards/distributions/dist:rew-http-final":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"distribution": map[string]any{
					"DistributionID": "dist:rew-http-final",
					"AccrualID":      "rew-http-final",
					"Status":         "submitted",
				},
			})
		case "/x/vpnrewards/accruals/rew-http-final":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"accrual": map[string]any{
					"AccrualID":      "rew-http-final",
					"OperationState": "confirmed",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:              srv.URL,
		APIKey:                "bridge-token",
		TrustedBridgeFinality: true,
		FinalityAuthToken:     "finality-token",
		QueueSize:             8,
		MaxRetries:            1,
		BaseBackoff:           5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	status, found, err := adapter.RewardIssueStatus(context.Background(), "rew-http-final")
	if err != nil {
		t.Fatalf("RewardIssueStatus: %v", err)
	}
	if !found || status != OperationStatusSubmitted {
		t.Fatalf("RewardIssueStatus got status=%s found=%v want submitted/found", status, found)
	}
	if got := <-seenPathCh; got != "/x/vpnrewards/distributions/dist:rew-http-final" {
		t.Fatalf("unexpected distribution status query path %q", got)
	}
	select {
	case got := <-seenPathCh:
		t.Fatalf("reward status should not derive finality from related accrual path %q", got)
	default:
	}
}

func TestCosmosAdapterHTTPBridgeFinalityRequiresTrustedBridgeFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x/vpnbilling/reservations/res-http-untrusted" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"reservation": map[string]any{
				"ReservationID": "res-http-untrusted",
				"Status":        "submitted",
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	status, found, err := adapter.FundReservationStatus(context.Background(), "res-http-untrusted")
	if err != nil {
		t.Fatalf("FundReservationStatus: %v", err)
	}
	if !found || status != OperationStatusSubmitted {
		t.Fatalf("FundReservationStatus got status=%s found=%v want submitted/found", status, found)
	}
}

func TestCosmosAdapterFundReservationDecodesMaterial(t *testing.T) {
	createdAt := time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x/vpnbilling/reservations/res-material" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"reservation": map[string]any{
				"ReservationID": "res-material",
				"SessionID":     "vpn-session-material",
				"SubjectID":     "cosmos1material",
				"AmountMicros":  123456,
				"Currency":      "TDPNC",
				"CreatedAt":     createdAt.Format(time.RFC3339Nano),
				"Status":        "confirmed",
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	reservation, found, err := adapter.FundReservation(context.Background(), "res-material")
	if err != nil {
		t.Fatalf("FundReservation: %v", err)
	}
	if !found {
		t.Fatalf("FundReservation found=%v want=true", found)
	}
	if reservation.ReservationID != "res-material" ||
		reservation.SessionID != "vpn-session-material" ||
		reservation.SubjectID != "cosmos1material" ||
		reservation.AmountMicros != 123456 ||
		reservation.Currency != "TDPNC" ||
		reservation.Status != OperationStatusConfirmed {
		t.Fatalf("unexpected reservation material: %+v", reservation)
	}
	if !reservation.CreatedAt.Equal(createdAt) {
		t.Fatalf("CreatedAt=%s want=%s", reservation.CreatedAt, createdAt)
	}
}

func TestCosmosAdapterFundReservationDecodesBridgeMaterialAliases(t *testing.T) {
	createdAtUnix := int64(1774483200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x/vpnbilling/reservations/res-bridge-material" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"reservation": map[string]any{
				"ReservationID": "res-bridge-material",
				"SessionID":     "vpn-session-bridge-material",
				"SubjectID":     "cosmos1bridgematerial",
				"Amount":        789000,
				"AssetDenom":    "uusdc",
				"CreatedAtUnix": createdAtUnix,
				"Status":        "confirmed",
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	reservation, found, err := adapter.FundReservation(context.Background(), "res-bridge-material")
	if err != nil {
		t.Fatalf("FundReservation: %v", err)
	}
	if !found {
		t.Fatalf("FundReservation found=%v want=true", found)
	}
	if reservation.ReservationID != "res-bridge-material" ||
		reservation.SessionID != "vpn-session-bridge-material" ||
		reservation.SubjectID != "cosmos1bridgematerial" ||
		reservation.AmountMicros != 789000 ||
		reservation.Currency != "uusdc" ||
		reservation.Status != OperationStatusConfirmed {
		t.Fatalf("unexpected bridge reservation material: %+v", reservation)
	}
	if want := time.Unix(createdAtUnix, 0).UTC(); !reservation.CreatedAt.Equal(want) {
		t.Fatalf("CreatedAt=%s want=%s", reservation.CreatedAt, want)
	}
}

func TestCosmosAdapterFundReservationRejectsMissingWalletMaterial(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "missing currency",
			body:    `{"ok":true,"reservation":{"ReservationID":"res-missing-wallet-material","SessionID":"vpn-session-missing-wallet-material","SubjectID":"cosmos1wallet","AmountMicros":123456,"Status":"confirmed"}}`,
			wantErr: "fund reservation requires currency",
		},
		{
			name:    "sponsor id is not wallet subject",
			body:    `{"ok":true,"reservation":{"ReservationID":"res-missing-wallet-material","SessionID":"vpn-session-missing-wallet-material","SponsorID":"cosmos1sponsor","AmountMicros":123456,"Currency":"TDPNC","Status":"confirmed"}}`,
			wantErr: "fund reservation requires subject_id",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/x/vpnbilling/reservations/res-missing-wallet-material" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:    srv.URL,
				QueueSize:   8,
				MaxRetries:  1,
				BaseBackoff: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			reservation, found, err := adapter.FundReservation(context.Background(), "res-missing-wallet-material")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("FundReservation error=%v want %q reservation=%+v found=%v", err, tc.wantErr, reservation, found)
			}
			if found {
				t.Fatalf("expected malformed wallet material not to be found")
			}
		})
	}
}

func TestCosmosAdapterFundReservationRejectsNonIntegerAmount(t *testing.T) {
	tests := []struct {
		name   string
		amount string
	}{
		{name: "fractional", amount: "123.5"},
		{name: "out_of_range", amount: "9223372036854775808"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/x/vpnbilling/reservations/res-bad-amount" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"ok":true,"reservation":{"ReservationID":"res-bad-amount","SessionID":"vpn-session-bad-amount","SubjectID":"cosmos1badamount","AmountMicros":`+tc.amount+`,"Currency":"TDPNC","Status":"confirmed"}}`)
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:    srv.URL,
				QueueSize:   8,
				MaxRetries:  1,
				BaseBackoff: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			reservation, found, err := adapter.FundReservation(context.Background(), "res-bad-amount")
			if err == nil {
				t.Fatalf("expected FundReservation to reject amount %s, got reservation=%+v found=%v", tc.amount, reservation, found)
			}
			if found {
				t.Fatalf("expected malformed amount not to be found")
			}
		})
	}
}

func TestCosmosAdapterHTTPBridgeDoesNotDeriveFinalityFromMissingStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x/vpnbilling/reservations/res-missing-status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"reservation": map[string]any{
				"ReservationID": "res-missing-status",
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	status, found, err := adapter.FundReservationStatus(context.Background(), "res-missing-status")
	if err == nil {
		t.Fatalf("expected missing status error, got status=%s found=%v", status, found)
	}
	if status != "" || found {
		t.Fatalf("expected missing status to avoid confirmed/found result, got status=%s found=%v err=%v", status, found, err)
	}
}

func TestCosmosAdapterSignedTxDoesNotDeriveHTTPBridgeFinality(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/x/vpnbilling/settlements/set-signed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"settlement": map[string]any{
					"SettlementID":   "set-signed",
					"ReservationID":  "res-signed",
					"OperationState": "submitted",
				},
			})
		case "/x/vpnbilling/reservations/res-signed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"reservation": map[string]any{
					"ReservationID": "res-signed",
					"Status":        "submitted",
				},
			})
		case "/x/vpnrewards/distributions/dist:rew-signed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"distribution": map[string]any{
					"DistributionID": "dist:rew-signed",
					"AccrualID":      "rew-signed",
					"Status":         "submitted",
				},
			})
		case "/x/vpnsponsor/delegations/sres-signed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"delegation": map[string]any{
					"ReservationID": "sres-signed",
					"Status":        "pending",
				},
			})
		case "/x/vpnslashing/evidence/ev-signed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"evidence": map[string]any{
					"EvidenceID": "ev-signed",
					"Status":     "submitted",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:        srv.URL,
		SubmitMode:      CosmosSubmitModeSignedTx,
		SignedTxChainID: "tdpn-test-1",
		SignedTxSigner:  "cosmos1signer",
		SignedTxSecret:  "signed-tx-test-secret",
		QueueSize:       8,
		MaxRetries:      1,
		BaseBackoff:     5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if status, found, err := adapter.SessionSettlementStatus(context.Background(), "set-signed"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("SessionSettlementStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.FundReservationStatus(context.Background(), "res-signed"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("FundReservationStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.RewardIssueStatus(context.Background(), "rew-signed"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("RewardIssueStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.SponsorReservationStatus(context.Background(), "sres-signed"); err != nil || !found || status != OperationStatusPending {
		t.Fatalf("SponsorReservationStatus got status=%s found=%v err=%v", status, found, err)
	}
	if status, found, err := adapter.SlashEvidenceStatus(context.Background(), "ev-signed"); err != nil || !found || status != OperationStatusSubmitted {
		t.Fatalf("SlashEvidenceStatus got status=%s found=%v err=%v", status, found, err)
	}
}

func TestCosmosAdapterListSlashEvidenceSendsFilteredQueryAndDecodesRecords(t *testing.T) {
	queryCh := make(chan map[string]string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x/vpnslashing/evidence" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		query := map[string]string{}
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				query[key] = values[0]
			}
		}
		queryCh <- query
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"evidence": []map[string]any{
				{
					"EvidenceID":      "ev-chain-list-1",
					"ProviderID":      "provider-chain-list",
					"SessionID":       "sess-chain-list",
					"ViolationType":   "invalid-settlement-proof",
					"ProofHash":       "sha256:" + strings.Repeat("a", 64),
					"SlashAmount":     123,
					"SlashDenom":      "uusdc",
					"SubmittedAtUnix": time.Date(2026, 4, 20, 2, 0, 0, 0, time.UTC).Unix(),
					"Status":          "submitted",
				},
			},
		})
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	start := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	got, err := adapter.ListSlashEvidence(context.Background(), SlashEvidenceFilter{
		SubjectID:         "provider-chain-list",
		SessionID:         "sess-chain-list",
		ViolationType:     "invalid-settlement-proof",
		ObservedAtOrAfter: start,
		ObservedBefore:    start.AddDate(0, 0, 7),
		IncludeFailed:     true,
		IncludeFailedSet:  true,
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence: %v", err)
	}
	query := <-queryCh
	if query["subject_id"] != "provider-chain-list" || query["session_id"] != "sess-chain-list" || query["violation_type"] != "invalid-settlement-proof" {
		t.Fatalf("unexpected query filter: %v", query)
	}
	if query["observed_at_or_after"] != start.Format(time.RFC3339) || query["observed_before"] != start.AddDate(0, 0, 7).Format(time.RFC3339) {
		t.Fatalf("unexpected time query filter: %v", query)
	}
	if query["include_failed"] != "1" {
		t.Fatalf("include_failed query=%q want 1 query=%v", query["include_failed"], query)
	}
	if len(got) != 1 {
		t.Fatalf("evidence len=%d want=1 evidence=%+v", len(got), got)
	}
	if got[0].SubjectID != "provider-chain-list" || got[0].EvidenceRef != "sha256:"+strings.Repeat("a", 64) || got[0].Currency != "UUSDC" {
		t.Fatalf("decoded evidence mismatch: %+v", got[0])
	}
	if got[0].ObservedAt.IsZero() || got[0].Status != OperationStatusSubmitted {
		t.Fatalf("decoded evidence observed/status mismatch: %+v", got[0])
	}

	_, err = adapter.ListSlashEvidence(context.Background(), SlashEvidenceFilter{
		SubjectID:        "provider-chain-list",
		IncludeFailed:    false,
		IncludeFailedSet: true,
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence explicit false: %v", err)
	}
	query = <-queryCh
	if query["include_failed"] != "0" {
		t.Fatalf("include_failed query=%q want 0 query=%v", query["include_failed"], query)
	}
}

func TestCosmosAdapterConfirmationQueriesReturnFalseOnNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	ok, err := adapter.HasSessionSettlement(context.Background(), "missing-settlement")
	if err != nil {
		t.Fatalf("HasSessionSettlement unexpected err: %v", err)
	}
	if ok {
		t.Fatalf("expected HasSessionSettlement=false for 404 query")
	}
}

func TestCosmosAdapterConfirmationQueriesRejectEmptyIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	testCases := []struct {
		name string
		call func(context.Context, string) (bool, error)
	}{
		{name: "session_settlement", call: adapter.HasSessionSettlement},
		{name: "reward_issue", call: adapter.HasRewardIssue},
		{name: "sponsor_reservation", call: adapter.HasSponsorReservation},
		{name: "slash_evidence", call: adapter.HasSlashEvidence},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := tc.call(context.Background(), " \t\n")
			if err == nil {
				t.Fatalf("expected validation error for empty id")
			}
			if ok {
				t.Fatalf("expected false when validation fails")
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("expected required-id validation error, got %v", err)
			}
		})
	}
}

func TestCosmosAdapterConfirmationQueriesReturnErrorOnNon404Status(t *testing.T) {
	for _, statusCode := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:    srv.URL,
				QueueSize:   8,
				MaxRetries:  1,
				BaseBackoff: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			testCases := []struct {
				name string
				call func(context.Context) (bool, error)
			}{
				{
					name: "session_settlement",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasSessionSettlement(ctx, "set-1")
					},
				},
				{
					name: "reward_issue",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasRewardIssue(ctx, "rew-1")
					},
				},
				{
					name: "sponsor_reservation",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasSponsorReservation(ctx, "sres-1")
					},
				},
				{
					name: "slash_evidence",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasSlashEvidence(ctx, "ev-1")
					},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ok, err := tc.call(context.Background())
					if err == nil {
						t.Fatalf("expected error for non-404 status %d", statusCode)
					}
					if ok {
						t.Fatalf("expected false when query fails")
					}
				})
			}
		})
	}
}

func TestCosmosAdapterSignedTxModeSubmitsBroadcast(t *testing.T) {
	type seenRequest struct {
		path string
		key  string
		body []byte
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- seenRequest{
			path: r.URL.Path,
			key:  r.Header.Get("Idempotency-Key"),
			body: body,
		}
		writeSignedTxSuccessResponse(w)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:        srv.URL,
		QueueSize:       8,
		MaxRetries:      1,
		BaseBackoff:     5 * time.Millisecond,
		SubmitMode:      CosmosSubmitModeSignedTx,
		SignedTxChainID: "tdpn-1",
		SignedTxSigner:  "signer1",
		SignedTxSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	ref, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-signed-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		TrafficProofRef:   "obj://traffic-proof/rew-signed-1",
		RewardMicros:      100,
		Currency:          "USD",
	})
	if err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}
	if ref != "reward:rew-signed-1" {
		t.Fatalf("unexpected ref id %q", ref)
	}

	select {
	case got := <-seenCh:
		if got.path != "/cosmos/tx/v1beta1/txs" {
			t.Fatalf("unexpected path %q", got.path)
		}
		if got.key != "reward:rew-signed-1" {
			t.Fatalf("unexpected idempotency key %q", got.key)
		}
		var req cosmosBroadcastRequest
		if err := json.Unmarshal(got.body, &req); err != nil {
			t.Fatalf("unmarshal broadcast request: %v", err)
		}
		if req.Mode != "BROADCAST_MODE_SYNC" {
			t.Fatalf("unexpected broadcast mode %q", req.Mode)
		}
		if req.Tx.ChainID != "tdpn-1" {
			t.Fatalf("unexpected chain id %q", req.Tx.ChainID)
		}
		if req.Tx.Signer != "signer1" {
			t.Fatalf("unexpected signer %q", req.Tx.Signer)
		}
		if req.Tx.MessageType != "/x/vpnrewards/issues" {
			t.Fatalf("unexpected message type %q", req.Tx.MessageType)
		}
		if req.Tx.IdempotencyKey != "reward:rew-signed-1" {
			t.Fatalf("unexpected tx idempotency key %q", req.Tx.IdempotencyKey)
		}
		if req.Tx.Signature == "" {
			t.Fatalf("expected non-empty signature")
		}
		var msg RewardIssue
		if err := json.Unmarshal(req.Tx.Message, &msg); err != nil {
			t.Fatalf("unmarshal tx message: %v", err)
		}
		if msg.RewardID != "rew-signed-1" {
			t.Fatalf("unexpected reward id %q", msg.RewardID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for signed-tx submit")
	}
}

func TestCosmosAdapterSignedTxModeRejectsMissingChainID(t *testing.T) {
	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:       "http://127.0.0.1:9999",
		SubmitMode:     CosmosSubmitModeSignedTx,
		SignedTxSigner: "signer-missing-chain-id",
		SignedTxSecret: "test-secret",
	})
	if err == nil {
		t.Fatalf("expected signed-tx chain_id validation error")
	}
	if !strings.Contains(err.Error(), "chain_id required") {
		t.Fatalf("expected chain_id required error, got %v", err)
	}
}

func TestCosmosAdapterSignedTxModeTreatsNonZeroTxCodeAsNonRetryableFailure(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tx_response":{"code":12,"raw_log":"insufficient fee"}}`)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:        srv.URL,
		QueueSize:       8,
		MaxRetries:      3,
		BaseBackoff:     5 * time.Millisecond,
		SubmitMode:      CosmosSubmitModeSignedTx,
		SignedTxChainID: "tdpn-test-1",
		SignedTxSigner:  "signer-nonzero-code",
		SignedTxSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-signed-code-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		TrafficProofRef:   "obj://traffic-proof/rew-signed-code-1",
		RewardMicros:      100,
		Currency:          "USD",
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 1
	}, "signed-tx deferred non-retryable entry")

	entry, ok := adapter.deferredOperationByID("reward:rew-signed-code-1")
	if !ok {
		t.Fatalf("expected deferred entry for reward:rew-signed-code-1")
	}
	if entry.replayable {
		t.Fatalf("expected non-zero tx code to be non-replayable")
	}
	if !strings.Contains(entry.lastError, "tx failed code 12") {
		t.Fatalf("expected tx code failure in last error, got %q", entry.lastError)
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly one attempt for non-retryable tx code failure, got %d", got)
	}
}

func TestCosmosAdapterSignedTxModeRetriesFailures(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:        srv.URL,
		QueueSize:       8,
		MaxRetries:      2,
		BaseBackoff:     5 * time.Millisecond,
		SubmitMode:      CosmosSubmitModeSignedTx,
		SignedTxChainID: "tdpn-test-1",
		SignedTxSigner:  "signer1",
		SignedTxSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
		EvidenceID:    "ev-1",
		SubjectID:     "subject-1",
		SessionID:     "sess-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:7f39f8317fbdb1988ef4c628eba02591d8cc0f0f67d330f140edca76163ffbee",
		SlashMicros:   1000,
		Currency:      "USD",
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&attempts) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected exactly 3 attempts (1 + 2 retries), got %d", got)
	}
}

func TestCosmosAdapterSubmitSlashEvidenceNormalizesObjectiveFieldsBeforeEnqueue(t *testing.T) {
	t.Run("trims_obj_ref", func(t *testing.T) {
		type seenRequest struct {
			path string
			key  string
			body []byte
		}
		seenCh := make(chan seenRequest, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			seenCh <- seenRequest{
				path: r.URL.Path,
				key:  r.Header.Get("Idempotency-Key"),
				body: body,
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    srv.URL,
			QueueSize:   4,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		ref, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
			EvidenceID:    "ev-normalize-obj-1",
			SubjectID:     "subject-1",
			SessionID:     "sess-1",
			ViolationType: "  DOUBLE-SIGN  ",
			EvidenceRef:   "  obj://validator/double-sign/block-12 \t",
			SlashMicros:   1000,
			Currency:      "USD",
		})
		if err != nil {
			t.Fatalf("SubmitSlashEvidence: %v", err)
		}
		if ref != "slash:ev-normalize-obj-1" {
			t.Fatalf("unexpected ref id %q", ref)
		}

		select {
		case got := <-seenCh:
			if got.path != "/x/vpnslashing/evidence" {
				t.Fatalf("unexpected path %q", got.path)
			}
			if got.key != "slash:ev-normalize-obj-1" {
				t.Fatalf("unexpected idempotency key %q", got.key)
			}
			var payload SlashEvidence
			if err := json.Unmarshal(got.body, &payload); err != nil {
				t.Fatalf("unmarshal slash evidence payload: %v", err)
			}
			if payload.ViolationType != "double-sign" {
				t.Fatalf("expected normalized violation type, got %q", payload.ViolationType)
			}
			if payload.EvidenceRef != "obj://validator/double-sign/block-12" {
				t.Fatalf("expected trimmed evidence ref, got %q", payload.EvidenceRef)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for slash evidence submit")
		}
	})

	t.Run("accepts_mixed_case_sha256_hex", func(t *testing.T) {
		type seenRequest struct {
			body []byte
		}
		seenCh := make(chan seenRequest, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			seenCh <- seenRequest{body: body}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    srv.URL,
			QueueSize:   4,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		const mixedCaseDigest = "6Ca13D52CA70c883E0f0Bb101E425a89E8624dE51dB2d2392593aF6A84118090"
		_, err = adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
			EvidenceID:    "ev-normalize-sha-1",
			SubjectID:     "subject-1",
			SessionID:     "sess-1",
			ViolationType: "double-sign",
			EvidenceRef:   "  sha256:" + mixedCaseDigest + "\n",
			SlashMicros:   1000,
			Currency:      "USD",
		})
		if err != nil {
			t.Fatalf("SubmitSlashEvidence: %v", err)
		}

		select {
		case got := <-seenCh:
			var payload SlashEvidence
			if err := json.Unmarshal(got.body, &payload); err != nil {
				t.Fatalf("unmarshal slash evidence payload: %v", err)
			}
			if payload.EvidenceRef != "sha256:"+mixedCaseDigest {
				t.Fatalf("expected mixed-case digest to remain intact after trim, got %q", payload.EvidenceRef)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for slash evidence submit")
		}
	})
}

func TestCosmosAdapterSubmitSlashEvidenceForcesSubmittedStatus(t *testing.T) {
	type seenRequest struct {
		body []byte
	}
	seenCh := make(chan seenRequest, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- seenRequest{body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   4,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	for _, status := range []OperationStatus{
		OperationStatusConfirmed,
		OperationStatusFailed,
		OperationStatusPending,
	} {
		if _, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
			EvidenceID:    "ev-force-" + string(status),
			SubjectID:     "subject-1",
			SessionID:     "sess-1",
			ViolationType: "double-sign",
			EvidenceRef:   "sha256:7f39f8317fbdb1988ef4c628eba02591d8cc0f0f67d330f140edca76163ffbee",
			SlashMicros:   1000,
			Currency:      "USD",
			Status:        status,
		}); err != nil {
			t.Fatalf("SubmitSlashEvidence with status %s: %v", status, err)
		}
	}

	for range 3 {
		select {
		case got := <-seenCh:
			var payload SlashEvidence
			if err := json.Unmarshal(got.body, &payload); err != nil {
				t.Fatalf("unmarshal slash evidence payload: %v", err)
			}
			if payload.Status != OperationStatusSubmitted {
				t.Fatalf("slash evidence payload status=%q want submitted", payload.Status)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for slash evidence submit")
		}
	}
}

func TestCosmosAdapterRejectsInvalidObjectiveSlashEvidenceBeforeEnqueue(t *testing.T) {
	for _, mode := range []struct {
		name string
		cfg  CosmosAdapterConfig
	}{
		{
			name: "http_mode",
			cfg: CosmosAdapterConfig{
				QueueSize:   4,
				MaxRetries:  1,
				BaseBackoff: 5 * time.Millisecond,
			},
		},
		{
			name: "signed_tx_mode",
			cfg: CosmosAdapterConfig{
				QueueSize:       4,
				MaxRetries:      1,
				BaseBackoff:     5 * time.Millisecond,
				SubmitMode:      CosmosSubmitModeSignedTx,
				SignedTxChainID: "tdpn-test-1",
				SignedTxSigner:  "signer-invalid-evidence",
				SignedTxSecret:  "test-secret",
			},
		},
	} {
		mode := mode
		t.Run(mode.name, func(t *testing.T) {
			var attempts int32
			attemptCh := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&attempts, 1)
				select {
				case attemptCh <- struct{}{}:
				default:
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cfg := mode.cfg
			cfg.Endpoint = srv.URL
			adapter, err := NewCosmosAdapter(cfg)
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			for _, tc := range []struct {
				name          string
				violationType string
				evidenceRef   string
				errContains   string
			}{
				{
					name:          "invalid_violation_type",
					violationType: "subjective-abuse",
					evidenceRef:   "sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
					errContains:   "requires objective violation_type",
				},
				{
					name:          "invalid_sha_ref",
					violationType: "double-sign",
					evidenceRef:   "sha256:abc123",
					errContains:   "requires objective evidence_ref",
				},
				{
					name:          "empty_ref_after_trim",
					violationType: "double-sign",
					evidenceRef:   " \t\n",
					errContains:   "requires objective evidence_ref",
				},
				{
					name:          "obj_ref_contains_internal_whitespace",
					violationType: "double-sign",
					evidenceRef:   "obj://validator/double-sign/block 12",
					errContains:   "requires objective evidence_ref",
				},
			} {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					_, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
						EvidenceID:    "ev-invalid-1",
						SubjectID:     "subject-1",
						SessionID:     "sess-1",
						ViolationType: tc.violationType,
						EvidenceRef:   tc.evidenceRef,
						SlashMicros:   1000,
						Currency:      "USD",
					})
					if err == nil {
						t.Fatalf("expected error for %s", tc.name)
					}
					if !strings.Contains(err.Error(), tc.errContains) {
						t.Fatalf("expected error to contain %q, got %v", tc.errContains, err)
					}
				})
			}

			select {
			case <-attemptCh:
				t.Fatalf("expected no network attempts for invalid slash evidence")
			case <-time.After(200 * time.Millisecond):
			}
			if got := atomic.LoadInt32(&attempts); got != 0 {
				t.Fatalf("expected no network attempts for invalid slash evidence, got %d", got)
			}
		})
	}
}

func TestCosmosAdapterSignedTxModeDoesNotRetryNonRetryable4xx(t *testing.T) {
	var attempts int32
	firstAttemptCh := make(chan struct{}, 1)
	secondAttemptCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			select {
			case firstAttemptCh <- struct{}{}:
			default:
			}
		}
		if n == 2 {
			select {
			case secondAttemptCh <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:        srv.URL,
		QueueSize:       8,
		MaxRetries:      3,
		BaseBackoff:     5 * time.Millisecond,
		SubmitMode:      CosmosSubmitModeSignedTx,
		SignedTxChainID: "tdpn-test-1",
		SignedTxSigner:  "signer-4xx",
		SignedTxSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
		EvidenceID:    "ev-4xx-signed-1",
		SubjectID:     "subject-1",
		SessionID:     "sess-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
		SlashMicros:   500,
		Currency:      "USD",
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	select {
	case <-firstAttemptCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first signed-tx attempt")
	}

	select {
	case <-secondAttemptCh:
		t.Fatalf("unexpected retry for non-retryable signed-tx 4xx response")
	case <-time.After(200 * time.Millisecond):
	}

	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly one signed-tx attempt, got %d", got)
	}
}

func TestCosmosAdapterSignedTxModeRetries429And503(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
	}{
		{name: "too_many_requests", statusCode: http.StatusTooManyRequests},
		{name: "service_unavailable", statusCode: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts int32
			doneCh := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := atomic.AddInt32(&attempts, 1)
				if n == 1 {
					w.WriteHeader(tc.statusCode)
					return
				}
				writeSignedTxSuccessResponse(w)
				select {
				case doneCh <- struct{}{}:
				default:
				}
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:        srv.URL,
				QueueSize:       8,
				MaxRetries:      2,
				BaseBackoff:     5 * time.Millisecond,
				SubmitMode:      CosmosSubmitModeSignedTx,
				SignedTxChainID: "tdpn-test-1",
				SignedTxSigner:  "signer-retry",
				SignedTxSecret:  "test-secret",
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
				RewardID:          "rew-signed-retry-1",
				ProviderSubjectID: "provider-1",
				SessionID:         "sess-1",
				TrafficProofRef:   "obj://traffic-proof/rew-signed-retry-1",
				RewardMicros:      100,
				Currency:          "USD",
			}); err != nil {
				t.Fatalf("SubmitRewardIssue: %v", err)
			}

			select {
			case <-doneCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for signed-tx retry success")
			}
			if got := atomic.LoadInt32(&attempts); got < 2 {
				t.Fatalf("expected at least two signed-tx attempts, got %d", got)
			}
		})
	}
}

func TestCosmosAdapterSignedTxModeReadsSecretFromFileAndIncludesKeyID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows temp file ACLs inherit sandbox groups; signed-tx secret file coverage is kept on non-Windows")
	}
	type seenRequest struct {
		path string
		body []byte
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- seenRequest{
			path: r.URL.Path,
			body: body,
		}
		writeSignedTxSuccessResponse(w)
	}))
	defer srv.Close()

	secretFile := filepath.Join(t.TempDir(), "signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte("  file-secret-value \n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           srv.URL,
		QueueSize:          8,
		MaxRetries:         1,
		BaseBackoff:        5 * time.Millisecond,
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-file-secret-1",
		SignedTxSigner:     "file-secret-signer",
		SignedTxSecretFile: secretFile,
		SignedTxKeyID:      "kms-key-1",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID: "set-file-secret-1",
		SessionID:    "sess-file-secret-1",
	}); err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}

	select {
	case got := <-seenCh:
		if got.path != "/cosmos/tx/v1beta1/txs" {
			t.Fatalf("unexpected path %q", got.path)
		}
		var req cosmosBroadcastRequest
		if err := json.Unmarshal(got.body, &req); err != nil {
			t.Fatalf("unmarshal signed-tx request: %v", err)
		}
		if req.Tx.KeyID != "kms-key-1" {
			t.Fatalf("unexpected key id %q", req.Tx.KeyID)
		}
		if req.Tx.Signature == "" {
			t.Fatalf("expected non-empty signature")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for signed-tx submit")
	}
}

func TestCosmosAdapterSignedTxModeRejectsEmptySecretFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows temp file ACLs inherit sandbox groups; signed-tx secret file coverage is kept on non-Windows")
	}
	secretFile := filepath.Join(t.TempDir(), "empty_signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte("   \n\t"), 0o600); err != nil {
		t.Fatalf("write empty secret file: %v", err)
	}

	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-test-1",
		SignedTxSigner:     "signer-empty-secret-file",
		SignedTxSecretFile: secretFile,
	})
	if err == nil {
		t.Fatalf("expected empty secret file validation error")
	}
}

func TestCosmosAdapterSignedTxModeRejectsUnreadableSecretFile(t *testing.T) {
	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-test-1",
		SignedTxSigner:     "signer-missing-secret-file",
		SignedTxSecretFile: filepath.Join(t.TempDir(), "missing_secret.txt"),
	})
	if err == nil {
		t.Fatalf("expected unreadable secret file validation error")
	}
}

func TestCosmosAdapterSignedTxModeRejectsSymlinkSecretFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior and policy differ on Windows")
	}

	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "signed_tx_secret_target.txt")
	if err := os.WriteFile(targetFile, []byte("symlink-secret"), 0o600); err != nil {
		t.Fatalf("write secret target file: %v", err)
	}
	linkedFile := filepath.Join(tempDir, "signed_tx_secret_link.txt")
	if err := os.Symlink(targetFile, linkedFile); err != nil {
		t.Skipf("symlink creation not available: %v", err)
	}

	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-test-1",
		SignedTxSigner:     "signer-symlink-secret-file",
		SignedTxSecretFile: linkedFile,
	})
	if err == nil {
		t.Fatalf("expected symlink secret file validation error")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected symlink rejection error, got %v", err)
	}
}

func TestCosmosAdapterSignedTxModeRejectsInsecureSecretFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not authoritative on Windows")
	}

	secretFile := filepath.Join(t.TempDir(), "insecure_signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte("insecure-secret"), 0o644); err != nil {
		t.Fatalf("write insecure secret file: %v", err)
	}

	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-test-1",
		SignedTxSigner:     "signer-insecure-secret-file",
		SignedTxSecretFile: secretFile,
	})
	if err == nil {
		t.Fatalf("expected insecure secret file permission validation error")
	}
	if !strings.Contains(err.Error(), "must not grant group/other permissions") {
		t.Fatalf("expected group/other permission error, got %v", err)
	}
}

func TestCosmosAdapterSignedTxModeRejectsOversizedSecretFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows temp file ACLs inherit sandbox groups; signed-tx secret file coverage is kept on non-Windows")
	}
	secretFile := filepath.Join(t.TempDir(), "large_signed_tx_secret.txt")
	largeSecret := strings.Repeat("a", int(cosmosSignedTxSecretFileMaxBytes)+1)
	if err := os.WriteFile(secretFile, []byte(largeSecret), 0o600); err != nil {
		t.Fatalf("write oversized secret file: %v", err)
	}

	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-test-1",
		SignedTxSigner:     "signer-oversized-secret-file",
		SignedTxSecretFile: secretFile,
	})
	if err == nil {
		t.Fatalf("expected oversized secret file validation error")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected max size validation error, got %v", err)
	}
}

func TestCosmosAdapterSignedTxModeAcceptsOwnerOnlySecretFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows temp file ACLs inherit sandbox groups; signed-tx secret file coverage is kept on non-Windows")
	}
	secretFile := filepath.Join(t.TempDir(), "secure_signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte("secure-secret"), 0o600); err != nil {
		t.Fatalf("write secure secret file: %v", err)
	}

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-test-1",
		SignedTxSigner:     "signer-secure-secret-file",
		SignedTxSecretFile: secretFile,
	})
	if err != nil {
		t.Fatalf("expected owner-only secret file to be accepted, got %v", err)
	}
	adapter.Close()
}

func TestCosmosAdapterFailureAfterEnqueueTransitionsToDeferredReplayable(t *testing.T) {
	var failWrites atomic.Bool
	failWrites.Store(true)
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnbilling/settlements" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&attempts, 1)
		if failWrites.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID: "set-deferred-1",
		SessionID:    "sess-deferred-1",
	}); err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 1
	}, "operation to be marked deferred")

	entry, ok := adapter.deferredOperationByID("settlement:set-deferred-1")
	if !ok {
		t.Fatalf("expected deferred entry for settlement:set-deferred-1")
	}
	if !entry.replayable {
		t.Fatalf("expected deferred entry to be replayable")
	}
	if entry.attempts < 1 {
		t.Fatalf("expected deferred entry attempts >= 1, got %d", entry.attempts)
	}
	if !strings.Contains(entry.lastError, "status 503") {
		t.Fatalf("expected deferred entry error to include status 503, got %q", entry.lastError)
	}

	failWrites.Store(false)
	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 0
	}, "deferred replay to clear")

	if got := atomic.LoadInt32(&attempts); got < 2 {
		t.Fatalf("expected at least two submit attempts, got %d", got)
	}
}

func TestCosmosAdapterDeferredBacklogCapMarksUnhealthyAndRejectsSubmissions(t *testing.T) {
	adapter := &CosmosAdapter{
		queue: make(chan cosmosQueuedOperation, 1),
		deferredOp: map[string]cosmosDeferredOperation{
			"op-1": {deferredAt: time.Unix(1, 0).UTC()},
			"op-2": {deferredAt: time.Unix(2, 0).UTC()},
			"op-3": {deferredAt: time.Unix(3, 0).UTC()},
		},
		deferredOpMax: 3,
	}

	err := adapter.markDeferredOperation(cosmosQueuedOperation{idempotencyKey: "op-4"}, 1, errors.New("retry"), true)
	if err == nil {
		t.Fatalf("expected deferred backlog insertion to fail once capacity is reached")
	}
	if !errors.Is(err, errCosmosAdapterDeferredBacklogLimitReached) {
		t.Fatalf("expected deferred backlog limit error, got %v", err)
	}

	if got := adapter.deferredOperationCount(); got != 3 {
		t.Fatalf("expected deferred backlog to stay capped at 3, got %d", got)
	}
	if _, ok := adapter.deferredOperationByID("op-1"); !ok {
		t.Fatalf("expected oldest deferred operation op-1 to be retained")
	}
	if _, ok := adapter.deferredOperationByID("op-4"); ok {
		t.Fatalf("expected newest deferred operation op-4 to be rejected once backlog is full")
	}

	if err := adapter.enqueue(cosmosQueuedOperation{idempotencyKey: "op-next"}); !errors.Is(err, errCosmosAdapterDeferredBacklogLimitReached) {
		t.Fatalf("expected enqueue rejection while adapter is unhealthy, got %v", err)
	}
	if err := adapter.Health(context.Background()); !errors.Is(err, errCosmosAdapterDeferredBacklogLimitReached) {
		t.Fatalf("expected health check to surface deferred backlog limit, got %v", err)
	}
}

func TestCosmosAdapterDrainDeferredPersistenceFailureMarksUnhealthy(t *testing.T) {
	adapter := &CosmosAdapter{
		queue: make(chan cosmosQueuedOperation, 1),
		deferredOp: map[string]cosmosDeferredOperation{
			"op-1": {deferredAt: time.Unix(1, 0).UTC()},
		},
		deferredOpMax: 1,
	}
	adapter.queue <- cosmosQueuedOperation{idempotencyKey: "op-lost"}

	adapter.drainQueuedOperationsToDeferred(errCosmosAdapterClosedWithBacklog)

	if got := adapter.deferredOperationCount(); got != 1 {
		t.Fatalf("expected deferred backlog to remain at cap after drain failure, got %d", got)
	}
	if _, ok := adapter.deferredOperationByID("op-lost"); ok {
		t.Fatalf("expected op-lost to be missing from deferred backlog when persistence fails")
	}

	failureCount, failureLast := adapter.deferredPersistenceFailureSnapshot()
	if failureCount != 1 {
		t.Fatalf("expected one deferred persistence failure, got %d", failureCount)
	}
	if !strings.Contains(failureLast, "op-lost") {
		t.Fatalf("expected deferred persistence failure detail to include idempotency key, got %q", failureLast)
	}
	if !strings.Contains(failureLast, "cosmos adapter deferred backlog limit reached") {
		t.Fatalf("expected deferred persistence failure detail to include backlog-limit marker, got %q", failureLast)
	}

	healthErr := adapter.Health(context.Background())
	if !errors.Is(healthErr, errCosmosAdapterDeferredBacklogLimitReached) {
		t.Fatalf("expected health check to fail with deferred backlog sentinel, got %v", healthErr)
	}
	if !strings.Contains(healthErr.Error(), "accepted operation persistence failures=1") {
		t.Fatalf("expected health failure detail to include deferred persistence count, got %q", healthErr)
	}
}

func TestCosmosAdapterEnqueueFailsClosedAfterDeferredPersistenceFailure(t *testing.T) {
	adapter := &CosmosAdapter{
		queue:                           make(chan cosmosQueuedOperation, 2),
		deferredOp:                      map[string]cosmosDeferredOperation{},
		deferredOpMax:                   4,
		deferredPersistenceFailureCount: 1,
		deferredPersistenceFailureLast:  "idempotency_key=op-lost defer_error=cosmos adapter deferred backlog limit reached: limit=1 current=1",
	}

	err := adapter.enqueue(cosmosQueuedOperation{idempotencyKey: "op-next"})
	if !errors.Is(err, errCosmosAdapterDeferredBacklogLimitReached) {
		t.Fatalf("expected enqueue to fail closed on deferred persistence failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "accepted operation persistence failures=1") {
		t.Fatalf("expected enqueue error to include deferred persistence failure detail, got %q", err)
	}
	if got := len(adapter.queue); got != 0 {
		t.Fatalf("expected enqueue rejection to leave queue untouched, got len=%d", got)
	}
}

func TestCosmosAdapterCloseDrainsBacklogToDeferred(t *testing.T) {
	startedCh := make(chan string, 2)
	releaseCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnrewards/issues" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		select {
		case startedCh <- r.Header.Get("Idempotency-Key"):
		default:
		}
		select {
		case <-releaseCh:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			return
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-close-1",
		ProviderSubjectID: "provider-close-1",
		SessionID:         "sess-close-1",
		TrafficProofRef:   "obj://traffic-proof/rew-close-1",
		RewardMicros:      100,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue first: %v", err)
	}
	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-close-2",
		ProviderSubjectID: "provider-close-2",
		SessionID:         "sess-close-2",
		TrafficProofRef:   "obj://traffic-proof/rew-close-2",
		RewardMicros:      200,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue second: %v", err)
	}

	select {
	case <-startedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first queued submit to start")
	}

	adapter.Close()
	close(releaseCh)

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 2
	}, "close backlog to deferred transition")

	first, ok := adapter.deferredOperationByID("reward:rew-close-1")
	if !ok {
		t.Fatalf("expected deferred entry for reward:rew-close-1")
	}
	if first.replayable {
		t.Fatalf("expected closed in-flight deferred entry to be non-replayable")
	}
	if first.lastError == "" {
		t.Fatalf("expected closed in-flight deferred entry to include a last error")
	}

	second, ok := adapter.deferredOperationByID("reward:rew-close-2")
	if !ok {
		t.Fatalf("expected deferred entry for reward:rew-close-2")
	}
	if second.replayable {
		t.Fatalf("expected closed queued deferred entry to be non-replayable")
	}
	if !strings.Contains(second.lastError, "closed with backlog") && !strings.Contains(second.lastError, "context canceled") {
		t.Fatalf("expected close-path deferred error marker, got %q", second.lastError)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-after-close",
		ProviderSubjectID: "provider-close-3",
		SessionID:         "sess-close-3",
		TrafficProofRef:   "obj://traffic-proof/rew-after-close",
		RewardMicros:      300,
	}); err == nil {
		t.Fatalf("expected submit after close to fail")
	}
}

func TestCosmosAdapterCloseDoesNotDropAcceptedConcurrentSubmissions(t *testing.T) {
	startedCh := make(chan string, 1)
	releaseCh := make(chan struct{})
	submittedIDs := map[string]struct{}{}
	var submittedMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnrewards/issues" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		select {
		case startedCh <- r.Header.Get("Idempotency-Key"):
		default:
		}
		select {
		case <-releaseCh:
			w.WriteHeader(http.StatusOK)
			submittedMu.Lock()
			submittedIDs[r.Header.Get("Idempotency-Key")] = struct{}{}
			submittedMu.Unlock()
		case <-r.Context().Done():
			return
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   256,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}

	seedID, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-race-seed",
		ProviderSubjectID: "provider-race-seed",
		SessionID:         "sess-race-seed",
		TrafficProofRef:   "obj://traffic-proof/rew-race-seed",
		RewardMicros:      100,
	})
	if err != nil {
		t.Fatalf("SubmitRewardIssue seed: %v", err)
	}

	select {
	case <-startedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for seed queued submit to start")
	}

	acceptedIDs := map[string]struct{}{seedID: struct{}{}}
	var acceptedMu sync.Mutex

	startCh := make(chan struct{})
	closeDone := make(chan struct{})
	go func() {
		<-startCh
		adapter.Close()
		close(closeDone)
	}()

	const concurrentSubmits = 128
	var wg sync.WaitGroup
	for i := 0; i < concurrentSubmits; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh
			rewardID := fmt.Sprintf("rew-race-%03d", i)
			id, submitErr := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
				RewardID:          rewardID,
				ProviderSubjectID: "provider-" + rewardID,
				SessionID:         "sess-" + rewardID,
				TrafficProofRef:   "obj://traffic-proof/" + rewardID,
				RewardMicros:      100,
			})
			if submitErr == nil {
				acceptedMu.Lock()
				acceptedIDs[id] = struct{}{}
				acceptedMu.Unlock()
			}
		}()
	}

	close(startCh)
	wg.Wait()
	close(releaseCh)

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for adapter close")
	}

	acceptedMu.Lock()
	defer acceptedMu.Unlock()
	for id := range acceptedIDs {
		if _, ok := adapter.deferredOperationByID(id); !ok {
			submittedMu.Lock()
			_, submitted := submittedIDs[id]
			submittedMu.Unlock()
			if !submitted {
				t.Fatalf("accepted idempotency key was neither deferred nor submitted after close: %s", id)
			}
		}
	}
}
