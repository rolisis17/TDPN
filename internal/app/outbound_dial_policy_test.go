package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

type stubClientOutboundResolver struct {
	ips map[string][]net.IPAddr
	err error
}

type outboundPolicyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f outboundPolicyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (s stubClientOutboundResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.ips[strings.ToLower(host)], nil
}

func TestConfigureClientOutboundDialPolicyDisablesProxyByDefault(t *testing.T) {
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	configureClientOutboundDialPolicy(client, false, false)

	policyRT, ok := client.Transport.(*clientOutboundPolicyRoundTripper)
	if !ok || policyRT == nil {
		t.Fatalf("expected client outbound policy round tripper")
	}
	transport, ok := policyRT.inner.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected wrapped client outbound transport clone")
	}
	if transport.Proxy != nil {
		t.Fatalf("expected client outbound transport proxy disabled by default")
	}
}

func TestConfigureClientOutboundDialPolicyAllowsProxyFromEnv(t *testing.T) {
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "1")

	client := &http.Client{}
	configureClientOutboundDialPolicy(client, false, false)

	policyRT, ok := client.Transport.(*clientOutboundPolicyRoundTripper)
	if !ok || policyRT == nil {
		t.Fatalf("expected client outbound policy round tripper")
	}
	transport, ok := policyRT.inner.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected wrapped client outbound transport clone")
	}
	if transport.Proxy == nil {
		t.Fatalf("expected proxy from environment when MTLS_ALLOW_PROXY_FROM_ENV=1")
	}
}

func TestResolveClientSafeDialAddressBlocksPrivateDNS(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("127.0.0.1")}},
		},
	}
	_, err := resolveClientSafeDialAddress(context.Background(), resolver, "example.com:443", false, false)
	if err == nil || !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("expected blocked address error, got %v", err)
	}
}

func TestResolveClientSafeDialAddressAllowsLocalhostLoopback(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"localhost": {{IP: net.ParseIP("127.0.0.1")}},
		},
	}
	got, err := resolveClientSafeDialAddress(context.Background(), resolver, "localhost:443", false, false)
	if err != nil {
		t.Fatalf("expected localhost to be allowed, got %v", err)
	}
	if got != "127.0.0.1:443" {
		t.Fatalf("unexpected dial address: %s", got)
	}
}

func TestResolveClientSafeDialAddressRejectsLocalhostMixedResolution(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"localhost": {
				{IP: net.ParseIP("198.51.100.24")},
				{IP: net.ParseIP("127.0.0.1")},
			},
		},
	}
	_, err := resolveClientSafeDialAddress(context.Background(), resolver, "localhost:443", false, false)
	if err == nil {
		t.Fatalf("expected mixed localhost resolution to be rejected")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressRejectsLocalhostMixedResolutionEvenWithDangerousOverride(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"localhost": {{IP: net.ParseIP("203.0.113.77")}},
		},
	}
	_, err := resolveClientSafeDialAddress(context.Background(), resolver, "localhost:443", true, false)
	if err == nil {
		t.Fatalf("expected localhost non-loopback resolution to be rejected")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressRejectsDotLocalhostLoopbackAlias(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"evil.localhost": {{IP: net.ParseIP("127.0.0.1")}},
		},
	}
	got, err := resolveClientSafeDialAddress(context.Background(), resolver, "evil.localhost:443", false, false)
	if err == nil {
		t.Fatalf("expected .localhost alias to be blocked, got %q", got)
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressRejectsDotLocalPublicResolution(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"entry-dev.local": {{IP: net.ParseIP("198.51.100.24")}},
		},
	}
	_, err := resolveClientSafeDialAddress(context.Background(), resolver, "entry-dev.local:443", false, false)
	if err == nil {
		t.Fatalf("expected .local public resolution to be rejected")
	}
	if !strings.Contains(err.Error(), "non-local address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressBlocksLiteralPrivateIPByDefault(t *testing.T) {
	_, err := resolveClientSafeDialAddress(context.Background(), nil, "10.0.0.5:443", false, false)
	if err == nil {
		t.Fatalf("expected literal private IP to be blocked by default")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressAllowsPrivateDNSWithDangerousOverride(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	got, err := resolveClientSafeDialAddress(context.Background(), resolver, "example.com:443", true, false)
	if err != nil {
		t.Fatalf("expected dangerous override to allow, got %v", err)
	}
	if got != "10.0.0.6:443" {
		t.Fatalf("unexpected dial address: %s", got)
	}
}

func TestResolveClientSafeDialAddressStrictModeBlocksPrivateDNSEvenWithDangerousOverride(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	_, err := resolveClientSafeDialAddress(context.Background(), resolver, "example.com:443", true, true)
	if err == nil {
		t.Fatalf("expected strict mode to block private DNS resolution even with dangerous override")
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressRejectsZoneHost(t *testing.T) {
	_, err := resolveClientSafeDialAddress(context.Background(), nil, "[fe80::1%eth0]:443", false, false)
	if err == nil || !strings.Contains(err.Error(), "zone identifier") {
		t.Fatalf("expected zone identifier rejection, got %v", err)
	}
}

func TestResolveClientSafeDialAddressStrictModeBlocksLiteralPrivateIP(t *testing.T) {
	_, err := resolveClientSafeDialAddress(context.Background(), nil, "10.0.0.5:443", false, true)
	if err == nil {
		t.Fatalf("expected strict mode to block literal private ip")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientSafeDialAddressStrictModeBlocksLiteralPrivateIPEvenWithDangerousOverride(t *testing.T) {
	_, err := resolveClientSafeDialAddress(context.Background(), nil, "10.0.0.5:443", true, true)
	if err == nil {
		t.Fatalf("expected strict mode to block literal private ip even with dangerous override")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientOutboundPolicyRoundTripperBlocksPrivateDestinationBeforeRoundTrip(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	called := false
	rt := &clientOutboundPolicyRoundTripper{
		inner: outboundPolicyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		resolver:                  resolver,
		allowDangerousPrivateDNS:  false,
		strictBlockPrivateLiteral: false,
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/v1/health", nil)
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

func TestClientOutboundPolicyRoundTripperAllowsDangerousOverride(t *testing.T) {
	resolver := stubClientOutboundResolver{
		ips: map[string][]net.IPAddr{
			"example.com": {{IP: net.ParseIP("10.0.0.6")}},
		},
	}
	called := false
	rt := &clientOutboundPolicyRoundTripper{
		inner: outboundPolicyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		resolver:                  resolver,
		allowDangerousPrivateDNS:  true,
		strictBlockPrivateLiteral: false,
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/v1/health", nil)
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
