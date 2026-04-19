package exit

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

type stubOutboundResolver struct {
	addrs map[string][]net.IPAddr
	err   error
}

func (s stubOutboundResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if s.err != nil {
		return nil, s.err
	}
	if out, ok := s.addrs[host]; ok {
		return out, nil
	}
	return nil, errors.New("host not found")
}

func TestConfigureOutboundDialPolicyDisablesProxyByDefault(t *testing.T) {
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	configureOutboundDialPolicy(client, false, false)

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected outbound transport clone")
	}
	if transport.Proxy != nil {
		t.Fatalf("expected outbound transport proxy disabled by default")
	}
}

func TestConfigureOutboundDialPolicyAllowsProxyFromEnv(t *testing.T) {
	t.Setenv("MTLS_ALLOW_PROXY_FROM_ENV", "1")

	client := &http.Client{}
	configureOutboundDialPolicy(client, false, false)

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected outbound transport clone")
	}
	if transport.Proxy == nil {
		t.Fatalf("expected proxy from environment when MTLS_ALLOW_PROXY_FROM_ENV=1")
	}
}

func TestResolveSafeDialAddressRejectsPrivateDNSAddress(t *testing.T) {
	t.Parallel()

	target, err := resolveSafeDialAddress(
		context.Background(),
		stubOutboundResolver{addrs: map[string][]net.IPAddr{
			"issuer.example": {{IP: net.ParseIP("10.10.10.10")}},
		}},
		"issuer.example:443",
		false,
		false,
	)
	if err == nil {
		t.Fatalf("expected private dns address to be blocked, got target=%q", target)
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSafeDialAddressAllowsLocalhostLoopback(t *testing.T) {
	t.Parallel()

	target, err := resolveSafeDialAddress(
		context.Background(),
		stubOutboundResolver{addrs: map[string][]net.IPAddr{
			"localhost": {{IP: net.ParseIP("127.0.0.1")}},
		}},
		"localhost:8082",
		false,
		false,
	)
	if err != nil {
		t.Fatalf("expected localhost loopback to be allowed, got %v", err)
	}
	if target != "127.0.0.1:8082" {
		t.Fatalf("unexpected target: %q", target)
	}
}

func TestResolveSafeDialAddressRejectsLocalhostMixedResolution(t *testing.T) {
	t.Parallel()

	target, err := resolveSafeDialAddress(
		context.Background(),
		stubOutboundResolver{addrs: map[string][]net.IPAddr{
			"localhost": {
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("203.0.113.12")},
			},
		}},
		"localhost:8082",
		false,
		false,
	)
	if err == nil {
		t.Fatalf("expected mixed localhost resolution to be blocked, got target=%q", target)
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSafeDialAddressRejectsDotLocalhostLoopbackAlias(t *testing.T) {
	t.Parallel()

	target, err := resolveSafeDialAddress(
		context.Background(),
		stubOutboundResolver{addrs: map[string][]net.IPAddr{
			"evil.localhost": {{IP: net.ParseIP("127.0.0.1")}},
		}},
		"evil.localhost:8082",
		false,
		false,
	)
	if err == nil {
		t.Fatalf("expected .localhost alias to be blocked, got target=%q", target)
	}
	if !strings.Contains(err.Error(), "blocked address classes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSafeDialAddressRejectsZoneIdentifierHost(t *testing.T) {
	t.Parallel()

	_, err := resolveSafeDialAddress(context.Background(), stubOutboundResolver{}, "[fe80::1%eth0]:8082", false, false)
	if err == nil {
		t.Fatal("expected zoned host to be rejected")
	}
}

func TestResolveSafeDialAddressBlocksLiteralPrivateIPByDefault(t *testing.T) {
	t.Parallel()

	_, err := resolveSafeDialAddress(context.Background(), stubOutboundResolver{}, "10.0.0.9:8082", false, false)
	if err == nil {
		t.Fatalf("expected literal private ip to be blocked by default")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSafeDialAddressDangerousOverrideAllowsPrivateDNS(t *testing.T) {
	t.Parallel()

	target, err := resolveSafeDialAddress(
		context.Background(),
		stubOutboundResolver{addrs: map[string][]net.IPAddr{
			"issuer.internal.example": {{IP: net.ParseIP("10.1.2.3")}},
		}},
		"issuer.internal.example:8443",
		true,
		false,
	)
	if err != nil {
		t.Fatalf("expected dangerous override to allow private dns host, got %v", err)
	}
	if target != "10.1.2.3:8443" {
		t.Fatalf("unexpected target: %q", target)
	}
}

func TestResolveSafeDialAddressStrictModeBlocksLiteralPrivateIP(t *testing.T) {
	t.Parallel()

	_, err := resolveSafeDialAddress(context.Background(), stubOutboundResolver{}, "10.0.0.9:8082", false, true)
	if err == nil {
		t.Fatalf("expected strict mode to block literal private ip")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSafeDialAddressStrictModeBlocksLiteralPrivateIPEvenWithDangerousOverride(t *testing.T) {
	t.Parallel()

	_, err := resolveSafeDialAddress(context.Background(), stubOutboundResolver{}, "10.0.0.9:8082", true, true)
	if err == nil {
		t.Fatalf("expected strict mode to block literal private ip even with dangerous override")
	}
	if !strings.Contains(err.Error(), "blocked by outbound dial policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsDisallowedOutboundDialIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "loopback", ip: "127.0.0.1", want: true},
		{name: "private", ip: "10.0.0.1", want: true},
		{name: "link-local-unicast", ip: "169.254.10.10", want: true},
		{name: "multicast", ip: "224.0.0.1", want: true},
		{name: "unspecified", ip: "0.0.0.0", want: true},
		{name: "public", ip: "8.8.8.8", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			if got := isDisallowedOutboundDialIP(ip); got != tc.want {
				t.Fatalf("isDisallowedOutboundDialIP(%q)=%t want=%t", tc.ip, got, tc.want)
			}
		})
	}
}

func TestNormalizeHTTPURLRejectsNonLoopbackHTTPInStrictMode(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "1")
	t.Setenv("EXIT_ALLOW_INSECURE_CONTROL_URL_HTTP", "")
	if got := normalizeHTTPURL("http://issuer.example.invalid:8082"); got != "" {
		t.Fatalf("expected non-loopback http URL to be rejected in strict mode, got %q", got)
	}
}

func TestNormalizeHTTPURLAllowsNonLoopbackHTTPWithDangerousOverride(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "1")
	t.Setenv("EXIT_ALLOW_INSECURE_CONTROL_URL_HTTP", "1")
	got := normalizeHTTPURL("http://issuer.example.invalid:8082")
	if got != "http://issuer.example.invalid:8082" {
		t.Fatalf("expected dangerous override to allow URL, got %q", got)
	}
}
