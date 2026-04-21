package directory

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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

func TestProviderTokenProofReplaySharedModeRejectsAcrossInstances(t *testing.T) {
	replayStorePath := filepath.Join(t.TempDir(), "provider_token_proof_replay.json")
	now := time.Unix(1_700_000_000, 0)

	first := &Service{
		providerTokenProofSeen:           make(map[string]time.Time),
		providerTokenProofStoreFile:      replayStorePath,
		providerTokenProofSharedFileMode: true,
		providerTokenProofLockTimeout:    time.Second,
	}
	second := &Service{
		providerTokenProofSeen:           make(map[string]time.Time),
		providerTokenProofStoreFile:      replayStorePath,
		providerTokenProofSharedFileMode: true,
		providerTokenProofLockTimeout:    time.Second,
	}

	if err := first.markProviderTokenProofReplay("tok-1", "nonce-1", now); err != nil {
		t.Fatalf("first mark replay failed: %v", err)
	}
	if got := first.providerTokenProofReplayCount(); got != 1 {
		t.Fatalf("first replay count=%d want 1", got)
	}

	err := second.markProviderTokenProofReplay("tok-1", "nonce-1", now.Add(time.Second))
	if err == nil {
		t.Fatal("expected shared replay store to reject nonce reuse across instances")
	}
	if !strings.Contains(err.Error(), "nonce replayed") {
		t.Fatalf("unexpected replay error: %v", err)
	}
	if got := second.providerTokenProofReplayCount(); got != 1 {
		t.Fatalf("second replay count=%d want 1 after shared load", got)
	}

	if err := second.markProviderTokenProofReplay("tok-1", "nonce-2", now.Add(2*time.Second)); err != nil {
		t.Fatalf("second mark with distinct nonce failed: %v", err)
	}
	if got := second.providerTokenProofReplayCount(); got != 2 {
		t.Fatalf("second replay count=%d want 2", got)
	}
}

func TestNewReadsProviderTokenProofReplayRedisConfig(t *testing.T) {
	t.Setenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR", "127.0.0.1:6379")
	t.Setenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_PASSWORD", "secret")
	t.Setenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DB", "2")
	t.Setenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_TLS", "1")
	t.Setenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_PREFIX", "gpm:test:directory:replay:")
	t.Setenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC", "9")

	s := New()
	if !s.providerTokenProofReplayRedisEnabled() {
		t.Fatalf("expected redis replay mode to be enabled")
	}
	if got := s.providerTokenProofReplayMode(); got != "redis" {
		t.Fatalf("provider replay mode=%q want=redis", got)
	}
	if got := s.providerTokenProofRedisAddr; got != "127.0.0.1:6379" {
		t.Fatalf("provider redis addr=%q want=%q", got, "127.0.0.1:6379")
	}
	if got := s.providerTokenProofRedisPassword; got != "secret" {
		t.Fatalf("provider redis password=%q want=%q", got, "secret")
	}
	if got := s.providerTokenProofRedisDB; got != 2 {
		t.Fatalf("provider redis db=%d want=2", got)
	}
	if !s.providerTokenProofRedisTLS {
		t.Fatalf("expected provider redis tls=true from env")
	}
	if got := s.providerTokenProofRedisPrefix; got != "gpm:test:directory:replay:" {
		t.Fatalf("provider redis prefix=%q", got)
	}
	if got := s.providerTokenProofRedisDial; got != 9*time.Second {
		t.Fatalf("provider redis dial timeout=%s want=9s", got)
	}
}

func TestProviderTokenProofReplayRedisModeRejectsAcrossInstances(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	now := time.Unix(1_700_000_000, 0)
	first := &Service{
		providerTokenProofSeen:        make(map[string]time.Time),
		providerTokenProofRedisAddr:   mr.Addr(),
		providerTokenProofRedisPrefix: "gpm:test:directory:replay:",
		providerTokenProofRedisDial:   time.Second,
	}
	second := &Service{
		providerTokenProofSeen:        make(map[string]time.Time),
		providerTokenProofRedisAddr:   mr.Addr(),
		providerTokenProofRedisPrefix: "gpm:test:directory:replay:",
		providerTokenProofRedisDial:   time.Second,
	}

	if err := first.markProviderTokenProofReplay("tok-redis-1", "nonce-1", now); err != nil {
		t.Fatalf("first redis replay mark failed: %v", err)
	}
	if err := second.markProviderTokenProofReplay("tok-redis-1", "nonce-1", now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("expected cross-instance redis replay rejection, got %v", err)
	}
	if err := second.markProviderTokenProofReplay("tok-redis-1", "nonce-2", now.Add(2*time.Second)); err != nil {
		t.Fatalf("second redis replay mark with distinct nonce failed: %v", err)
	}
}

func TestProviderTokenProofReplayRedisModeFailureFailsClosed(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	s := &Service{
		providerTokenProofSeen:        make(map[string]time.Time),
		providerTokenProofRedisAddr:   mr.Addr(),
		providerTokenProofRedisPrefix: "gpm:test:directory:replay:",
		providerTokenProofRedisDial:   time.Second,
	}

	if err := s.markProviderTokenProofReplay("tok-redis-fail-1", "nonce-1", now); err != nil {
		t.Fatalf("seed redis replay mark failed: %v", err)
	}
	mr.Close()

	err = s.markProviderTokenProofReplay("tok-redis-fail-1", "nonce-2", now.Add(time.Second))
	if err == nil {
		t.Fatal("expected redis replay failure to fail closed")
	}
	if !strings.Contains(err.Error(), "redis") {
		t.Fatalf("expected redis context in failure, got %v", err)
	}
}
