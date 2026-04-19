package directory

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPickEntryEndpointRotates(t *testing.T) {
	s := &Service{entryEndpoints: []string{"a", "b"}, endpointRotateSec: 10}
	if got := s.pickEntryEndpoint(time.Unix(0, 0)); got != "a" {
		t.Fatalf("expected a, got %s", got)
	}
	if got := s.pickEntryEndpoint(time.Unix(10, 0)); got != "b" {
		t.Fatalf("expected b, got %s", got)
	}
}

func TestHandleHealth(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("expected ok body, got %q", rr.Body.String())
	}
}

func TestHandleHealthMethodNotAllowed(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodPost, "/v1/health", nil)
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestValidateRuntimeConfigPublicBindAdminTokenRequiresMTLS(t *testing.T) {
	s := &Service{
		addr:       "0.0.0.0:8081",
		adminToken: "super-secret-admin-token",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection without mTLS for admin-token mode")
	}
	if !strings.Contains(err.Error(), "public bind with DIRECTORY_ADMIN_TOKEN requires MTLS_ENABLE=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindAdminTokenAllowsDangerousOverride(t *testing.T) {
	t.Setenv("DIRECTORY_ALLOW_DANGEROUS_INSECURE_ADMIN_PUBLIC_BIND", "1")
	s := &Service{
		addr:       "0.0.0.0:8081",
		adminToken: "super-secret-admin-token",
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected explicit dangerous override to allow config, got %v", err)
	}
}

func TestParseDNSSeedsNormalizesAndFilters(t *testing.T) {
	got := parseDNSSeeds([]string{
		" Example.com. ",
		"example.com",
		"DIR.EXAMPLE.COM.",
		"http://bad.example.com",
		"bad/path",
		"",
		"dir.example.com",
	})
	want := []string{"example.com", "dir.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected dns seeds: got=%v want=%v", got, want)
	}
}

func TestParseDNSPeerHintRecordKeyValue(t *testing.T) {
	pubRaw := make([]byte, ed25519.PublicKeySize)
	for i := range pubRaw {
		pubRaw[i] = byte(i + 1)
	}
	pubKey := base64.RawURLEncoding.EncodeToString(pubRaw)

	hint, ok := parseDNSPeerHintRecord("url=dir.example.com;operator=op-a;pub_key=" + pubKey)
	if !ok {
		t.Fatal("expected record to parse")
	}
	if hint.URL != "https://dir.example.com" {
		t.Fatalf("unexpected url: %q", hint.URL)
	}
	if hint.Operator != "op-a" {
		t.Fatalf("unexpected operator: %q", hint.Operator)
	}
	if hint.PubKey != pubKey {
		t.Fatalf("unexpected pubkey: %q", hint.PubKey)
	}
}

func TestParseDNSPeerHintRecordURLOnly(t *testing.T) {
	hint, ok := parseDNSPeerHintRecord("https://peer.example.com")
	if !ok {
		t.Fatal("expected url-only record to parse")
	}
	if hint.URL != "https://peer.example.com" {
		t.Fatalf("unexpected url: %q", hint.URL)
	}
	if hint.Operator != "" || hint.PubKey != "" {
		t.Fatalf("expected empty optional fields, got operator=%q pub_key=%q", hint.Operator, hint.PubKey)
	}
}

func TestParseDNSPeerHintRecordRejectsInvalidURL(t *testing.T) {
	if _, ok := parseDNSPeerHintRecord("url=localhost:8081;operator=op-a"); ok {
		t.Fatal("expected localhost discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("url=http://127.0.0.1:8081;operator=op-a"); ok {
		t.Fatal("expected loopback discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("url=http://169.254.169.254:80;operator=op-a"); ok {
		t.Fatal("expected link-local discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("url=https://10.0.0.10:8081;operator=op-a"); ok {
		t.Fatal("expected private discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("url=http://127.1:8081;operator=op-a"); ok {
		t.Fatal("expected loopback alias discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("url=http://2130706433:8081;operator=op-a"); ok {
		t.Fatal("expected numeric loopback alias discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("url=https://[fe80::1%25eth0]:8081;operator=op-a"); ok {
		t.Fatal("expected zoned ipv6 discovery url to be rejected")
	}
	if _, ok := parseDNSPeerHintRecord("this is not a valid record"); ok {
		t.Fatal("expected invalid record to be rejected")
	}
}

func TestStrictControlHostRejectsAmbiguousNumericAliases(t *testing.T) {
	tests := []string{"127.1", "2130706433", "localhost.", "fe80::1%eth0"}
	for _, host := range tests {
		if !isDisallowedStrictControlHost(host) {
			t.Fatalf("expected strict control host %q to be rejected", host)
		}
	}
}

func TestParseDNSPeerHintRecordAllowsPublicIPAddress(t *testing.T) {
	hint, ok := parseDNSPeerHintRecord("url=https://8.8.8.8:8443;operator=op-public")
	if !ok {
		t.Fatal("expected public ip discovery url to parse")
	}
	if hint.URL != "https://8.8.8.8:8443" {
		t.Fatalf("unexpected url: %q", hint.URL)
	}
	if hint.Operator != "op-public" {
		t.Fatalf("unexpected operator: %q", hint.Operator)
	}
}

func TestParseDNSPeerHintsMergesDuplicateURLHints(t *testing.T) {
	pubRaw := make([]byte, ed25519.PublicKeySize)
	for i := range pubRaw {
		pubRaw[i] = byte(255 - i)
	}
	pubKey := base64.RawURLEncoding.EncodeToString(pubRaw)

	got := parseDNSPeerHints([]string{
		"url=dir.example.com;operator=op-a",
		"url=dir.example.com;pub_key=" + pubKey,
		"url=https://other.example.com",
		"garbage",
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 hints, got %d", len(got))
	}
	if got[0].URL != "https://dir.example.com" {
		t.Fatalf("unexpected first url: %q", got[0].URL)
	}
	if got[0].Operator != "op-a" {
		t.Fatalf("unexpected first operator: %q", got[0].Operator)
	}
	if got[0].PubKey != pubKey {
		t.Fatalf("unexpected first pubkey: %q", got[0].PubKey)
	}
	if got[1].URL != "https://other.example.com" {
		t.Fatalf("unexpected second url: %q", got[1].URL)
	}
}
