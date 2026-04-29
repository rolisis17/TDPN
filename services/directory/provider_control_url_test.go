package directory

import (
	"strings"
	"testing"
)

func TestValidateProviderControlURLStrictRejectsHTTP(t *testing.T) {
	err := validateProviderControlURL("http://198.51.100.10:8443", "198.51.100.10:51820", true)
	if err == nil {
		t.Fatalf("expected strict mode to reject non-https control url")
	}
	if !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("expected strict https error, got %v", err)
	}
}

func TestValidateProviderControlURLStrictAcceptsHTTPS(t *testing.T) {
	if err := validateProviderControlURL("https://198.51.100.10:8443", "198.51.100.10:51820", true); err != nil {
		t.Fatalf("expected strict mode to accept matching https control url, got %v", err)
	}
}

func TestValidateProviderControlURLStrictRejectsPathPrefix(t *testing.T) {
	err := validateProviderControlURL("https://198.51.100.10:8443/provider-prefix", "198.51.100.10:51820", true)
	if err == nil {
		t.Fatalf("expected strict mode to reject control_url path prefix")
	}
	if !strings.Contains(err.Error(), "path prefixes are not allowed") {
		t.Fatalf("expected strict path-prefix error, got %v", err)
	}
}

func TestValidateProviderControlURLStrictRejectsCGNATLiteral(t *testing.T) {
	for _, host := range []string{"100.64.0.1", "100.127.255.254"} {
		err := validateProviderControlURL("https://"+host+":8443", host+":51820", true)
		if err == nil {
			t.Fatalf("expected strict mode to reject CGNAT control url host %s", host)
		}
		if !strings.Contains(err.Error(), "host is not allowed") {
			t.Fatalf("expected strict host error for %s, got %v", host, err)
		}
	}
}

func TestValidateProviderControlURLRejectsAuthorityModifiers(t *testing.T) {
	err := validateProviderControlURL("https://token@198.51.100.10:8443?x=1#fragment", "198.51.100.10:51820", false)
	if err == nil {
		t.Fatalf("expected control_url with userinfo/query/fragment to be rejected")
	}
	if !strings.Contains(err.Error(), "must not include userinfo") {
		t.Fatalf("expected authority modifier error, got %v", err)
	}
}

func TestValidateProviderControlURLNonStrictAllowsHTTP(t *testing.T) {
	if err := validateProviderControlURL("http://198.51.100.10:8443", "198.51.100.10:51820", false); err != nil {
		t.Fatalf("expected non-strict mode to allow matching http control url, got %v", err)
	}
}
