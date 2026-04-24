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

func TestValidateProviderControlURLNonStrictAllowsHTTP(t *testing.T) {
	if err := validateProviderControlURL("http://198.51.100.10:8443", "198.51.100.10:51820", false); err != nil {
		t.Fatalf("expected non-strict mode to allow matching http control url, got %v", err)
	}
}
